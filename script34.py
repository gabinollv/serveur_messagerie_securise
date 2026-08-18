import json
import os
import time
import tempfile
import eventlet
import socketio
import bcrypt

# Optimisation Eventlet pour E/S asynchrones
eventlet.monkey_patch()

# Limite de la taille des paquets à 512 KB
MAX_MESSAGE_SIZE = 512 * 1024

sio = socketio.Server(
    cors_allowed_origins='*',
    async_mode='eventlet',
    max_http_buffer_size=MAX_MESSAGE_SIZE
)
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"
FICHIER_PROFILS = "profils.json"  # Fichier pour stocker les emails, tels et liens
tentatives_echouees = {}

# Mappage strict pour prévenir l'usurpation d'identité
utilisateurs = {}     # { pseudo: sid }
sid_vers_pseudo = {}  # { sid: pseudo }

def nettoyer_rate_limit():
    maintenant = time.time()
    cles_a_supprimer = [
        ip for ip, info in tentatives_echouees.items()
        if maintenant > info['bloque_jusqu_a'] and info['compteur'] == 0
    ]
    for ip in cles_a_supprimer:
        del tentatives_echouees[ip]

def verifier_rate_limit(ip):
    nettoyer_rate_limit()
    maintenant = time.time()
    info = tentatives_echouees.get(ip, {'compteur': 0, 'bloque_jusqu_a': 0})
    if maintenant < info['bloque_jusqu_a']:
        return False, f"Trop d'échecs. Réessayez dans {int(info['bloque_jusqu_a'] - maintenant)}s."
    return True, ""

def enregistrer_echec(ip):
    maintenant = time.time()
    info = tentatives_echouees.get(ip, {'compteur': 0, 'bloque_jusqu_a': 0})
    info['compteur'] += 1
    if info['compteur'] >= 5:
        info['bloque_jusqu_a'] = maintenant + 60
        info['compteur'] = 0
    tentatives_echouees[ip] = info

def reinitialiser_echecs(ip):
    if ip in tentatives_echouees:
        del tentatives_echouees[ip]

def charger_json(fichier):
    if os.path.exists(fichier):
        try:
            with open(fichier, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERREUR] Impossible de lire {fichier}: {e}")
    return {}

def sauvegarder_json_atomique(donnees, fichier):
    try:
        dir_name = os.path.dirname(fichier) or '.'
        with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name, encoding='utf-8') as tf:
            json.dump(donnees, tf, indent=4)
            temp_name = tf.name
        os.replace(temp_name, fichier)
    except Exception as e:
        print(f"[ERREUR] Sauvegarde {fichier} a échoué : {e}")

comptes = charger_json(FICHIER_COMPTES)
profils = charger_json(FICHIER_PROFILS)

def diffuser_liste_contacts():
    liste_membres = list(comptes.keys())
    sio.emit('liste_contacts', liste_membres)

@sio.event
def connect(sid, environ):
    print(f"[CONNECT] Nouvelle connexion socket établie : SID={sid}")

@sio.event
def enregistrer_utilisateur(sid, data):
    if not isinstance(data, dict):
        return

    environ = sio.get_environ(sid)
    ip = environ.get('REMOTE_ADDR', sid) if environ else sid

    autorise, msg_erreur = verifier_rate_limit(ip)
    if not autorise:
        sio.emit('reponse_connexion', {'succes': False, 'message': msg_erreur}, room=sid)
        return

    pseudo = str(data.get('pseudo', '')).strip()
    code = str(data.get('code', '')).strip()

    if not pseudo or not code or len(pseudo) > 64 or len(code) > 64:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Requête d'authentification invalide."}, room=sid)
        return

    if pseudo not in comptes:
        sel = bcrypt.gensalt(rounds=12)
        comptes[pseudo] = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        sauvegarder_json_atomique(comptes, FICHIER_COMPTES)
        
        # Initialisation d'un profil vide
        profils[pseudo] = {"email": "Non renseigné", "phone": "Non renseigné", "links": []}
        sauvegarder_json_atomique(profils, FICHIER_PROFILS)
        
        utilisateurs[pseudo] = sid
        sid_vers_pseudo[sid] = pseudo
        reinitialiser_echecs(ip)
        
        print(f"[INSCRIPTION] Nouvel utilisateur : {pseudo} (SID: {sid})")
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte sécurisé créé pour '{pseudo}'."}, room=sid)
        diffuser_liste_contacts()
    else:
        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            ancien_sid = utilisateurs.get(pseudo)
            if ancien_sid and ancien_sid in sid_vers_pseudo:
                del sid_vers_pseudo[ancien_sid]

            utilisateurs[pseudo] = sid
            sid_vers_pseudo[sid] = pseudo
            reinitialiser_echecs(ip)
            
            print(f"[CONNEXION] {pseudo} authentifié avec succès (SID: {sid})")
            sio.emit('reponse_connexion', {'succes': True, 'message': f"Authentifié en tant que '{pseudo}'."}, room=sid)
            diffuser_liste_contacts()
        else:
            enregistrer_echec(ip)
            print(f"[ECHEC CONNEXION] Identifiants invalides pour {pseudo}")
            sio.emit('reponse_connexion', {'succes': False, 'message': "Identifiants invalides !"}, room=sid)

@sio.event
def obtenir_liste_contacts(sid, data=None):
    sio.emit('liste_contacts', list(comptes.keys()), room=sid)

@sio.event
def envoyer_demande_ami(sid, data):
    if not isinstance(data, dict): return
    demandeur = sid_vers_pseudo.get(sid)
    if not demandeur:
        sio.emit('erreur_message', {'message': "Votre session n'est pas reconnue. Veuillez vous reconnecter."}, room=sid)
        return

    destinataire = str(data.get('destinataire', '')).strip()
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('demande_ami_recue', {'demandeur': demandeur}, room=target_sid)
    else:
        sio.emit('erreur_message', {'message': f"'{destinataire}' est hors ligne ou introuvable."}, room=sid)

@sio.event
def reponse_demande_ami(sid, data):
    if not isinstance(data, dict): return
    repondeur = sid_vers_pseudo.get(sid)
    if not repondeur: return

    demandeur = str(data.get('demandeur', '')).strip()
    accepte = bool(data.get('accepte', False))

    if demandeur in utilisateurs:
        target_sid = utilisateurs[demandeur]
        sio.emit('reponse_demande_ami_recue', {'contact': repondeur, 'accepte': accepte}, room=target_sid)

@sio.event
def envoyer_message_direct(sid, data):
    if not isinstance(data, dict):
        return

    expediteur_reel = sid_vers_pseudo.get(sid)
    if not expediteur_reel:
        print(f"[SERVEUR REJET] Session non reconnue pour le SID: {sid}")
        sio.emit(
            "erreur_message",
            {"message": "Votre session n'est pas reconnue."},
            room=sid,
        )
        return

    destinataire = str(data.get("destinataire", "")).strip()
    type_msg = str(data.get("type", ""))

    print(
        f"[SERVEUR ROUTAGE] Message de '{expediteur_reel}' vers '{destinataire}' (Type: {type_msg})"
    )

    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        payload_securise = {
            "expediteur": expediteur_reel,
            "destinataire": destinataire,
            "type": type_msg,
            "contenu": str(data.get("contenu", "")),
            "signature": str(data.get("signature", "")),
        }
        sio.emit("reception_message", payload_securise, room=target_sid)
        print(
            f"[SERVEUR SUCCÈS] Transmis à {destinataire} (SID: {target_sid})"
        )
    else:
        print(
            f"[SERVEUR ERREUR] Destinataire '{destinataire}' introuvable ou hors ligne"
        )
        sio.emit(
            "erreur_message",
            {
                "message": f"L'utilisateur '{destinataire}' est hors ligne ou introuvable."
            },
            room=sid,
        )

# --- NOUVEAU : Gestion des profils ---
@sio.event
def maj_infos_contact(sid, data):
    """Reçu quand un utilisateur modifie son propre profil."""
    pseudo = sid_vers_pseudo.get(sid)
    if not pseudo or not isinstance(data, dict): return
    
    # On met à jour le dictionnaire et on sauvegarde
    if pseudo not in profils:
        profils[pseudo] = {}
        
    profils[pseudo]["email"] = data.get("email", "Non renseigné")
    profils[pseudo]["phone"] = data.get("phone", "Non renseigné")
    profils[pseudo]["links"] = data.get("links", [])
    
    sauvegarder_json_atomique(profils, FICHIER_PROFILS)
    print(f"[PROFIL] Mise à jour des informations pour {pseudo}")

@sio.event
def demander_infos_contact(sid, data):
    """Reçu quand un utilisateur veut voir le profil d'un contact."""
    if not isinstance(data, dict): return
    
    cible = data.get("pseudo")
    infos_cible = profils.get(cible, {})
    
    reponse = {
        "pseudo": cible,
        "email": infos_cible.get("email", "Non renseigné"),
        "phone": infos_cible.get("phone", "Non renseigné"),
        "links": infos_cible.get("links", [])
    }
    sio.emit("reception_infos_contact", reponse, to=sid)

@sio.event
def disconnect(sid):
    if sid in sid_vers_pseudo:
        pseudo = sid_vers_pseudo.pop(sid)
        if utilisateurs.get(pseudo) == sid:
            del utilisateurs[pseudo]
            print(f"[DÉCONNEXION] {pseudo} s'est totalement déconnecté (SID: {sid})")
            diffuser_liste_contacts()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR] Écoute active sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
