import json
import os
import time
import tempfile
import eventlet
import socketio
import bcrypt

# Optimisation Eventlet pour E/S asynchrones
eventlet.monkey_patch()

# Limite stricte de la taille des paquets à 32 KB pour contrer les DoS par payload
MAX_MESSAGE_SIZE = 32 * 1024 

sio = socketio.Server(
    cors_allowed_origins='*',
    async_mode='eventlet',
    max_http_buffer_size=MAX_MESSAGE_SIZE
)
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"
tentatives_echouees = {}

# Mappage strict pour prévenir l'usurpation d'identité (Spoofing)
utilisateurs = {}     # { pseudo: sid }
sid_vers_pseudo = {}  # { sid: pseudo }

def nettoyer_rate_limit():
    """Purge dynamique des données de rate-limiting pour éviter la fuite mémoire (DoS)."""
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

def charger_comptes():
    if os.path.exists(FICHIER_COMPTES):
        try:
            with open(FICHIER_COMPTES, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERREUR CRITIQUE] Impossible de lire {FICHIER_COMPTES}: {e}")
            return {}
    return {}

def sauvegarder_comptes_atomique():
    """Écriture atomique sécurisée sur le disque dur pour prévenir la corruption des comptes."""
    try:
        dir_name = os.path.dirname(FICHIER_COMPTES) or '.'
        with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name, encoding='utf-8') as tf:
            json.dump(comptes, tf, indent=4)
            temp_name = tf.name
        os.replace(temp_name, FICHIER_COMPTES)
    except Exception as e:
        print(f"[ERREUR CRITIQUE] Sauvegarde atomique a échoué : {e}")

comptes = charger_comptes()

def diffuser_liste_contacts():
    """Diffuse la liste de tous les inscrits (ou connectés) à tout le monde."""
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
        sauvegarder_comptes_atomique()
        
        utilisateurs[pseudo] = sid
        sid_vers_pseudo[sid] = pseudo
        reinitialiser_echecs(ip)
        
        print(f"[INSCRIPTION] Nouvel utilisateur : {pseudo} (SID: {sid})")
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte sécurisé créé pour '{pseudo}'."}, room=sid)
        diffuser_liste_contacts()
    else:
        # Authentification d'un compte existant / Reconnexion
        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            # Nettoyage de la liaison de l'ancien SID si l'utilisateur change de socket
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
    if not isinstance(data, dict):
        return
    
    demandeur = sid_vers_pseudo.get(sid)
    if not demandeur:
        return

    destinataire = str(data.get('destinataire', '')).strip()
    
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('demande_ami_recue', {'demandeur': demandeur}, room=target_sid)

@sio.event
def reponse_demande_ami(sid, data):
    if not isinstance(data, dict):
        return

    repondeur = sid_vers_pseudo.get(sid)
    if not repondeur:
        return

    demandeur = str(data.get('demandeur', '')).strip()
    accepte = bool(data.get('accepte', False))

    if demandeur in utilisateurs:
        target_sid = utilisateurs[demandeur]
        sio.emit('reponse_demande_ami_recue', {
            'contact': repondeur,
            'accepte': accepte
        }, room=target_sid)

@sio.event
def envoyer_message_direct(sid, data):
    if not isinstance(data, dict):
        print(f"[ERREUR FORMAT] Données non dictionnaire reçues de {sid}")
        return
    
    # 1. Vérification de l'expéditeur
    expediteur_reel = sid_vers_pseudo.get(sid)
    if not expediteur_reel:
        print(f"[REJET MESSAGE] Expéditeur non identifié pour SID={sid}. Session probablement expirée.")
        sio.emit('erreur_message', {'message': "Votre session n'est pas reconnue. Veuillez vous reconnecter."}, room=sid)
        return

    destinataire = str(data.get('destinataire', '')).strip()
    print(f"[TENTATIVE MESSAGE] De '{expediteur_reel}' vers '{destinataire}' (Type: {data.get('type')})")

    # 2. Vérification du destinataire
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        
        payload_securise = {
            'expediteur': expediteur_reel,
            'destinataire': destinataire,
            'type': str(data.get('type', '')),
            'contenu': str(data.get('contenu', '')),
            'signature': str(data.get('signature', ''))
        }
        
        # CORRECTIF : le client écoute 'reception_message', pas 'message_direct'.
        # C'était le bug empêchant tout affichage côté destinataire (handshake ET messages).
        sio.emit('reception_message', payload_securise, room=target_sid)
        print(f"[SUCCÈS TRANSFERT] Message transmis à {destinataire} (SID: {target_sid})")
    else:
        print(f"[ÉCHEC TRANSFERT] Destinataire '{destinataire}' non connecté sur le serveur.")
        print(f"--> Utilisateurs actuellement actifs : {list(utilisateurs.keys())}")
        sio.emit('erreur_message', {'message': f"L'utilisateur '{destinataire}' est hors ligne ou introuvable."}, room=sid)

@sio.event
def disconnect(sid):
    if sid in sid_vers_pseudo:
        pseudo = sid_vers_pseudo.pop(sid)
        
        # CORRECTIF : On ne supprime l'utilisateur de 'utilisateurs' QUE SI
        # le SID déconnecté est bien le SID actif (évite d'effacer une reconnexion récente)
        if utilisateurs.get(pseudo) == sid:
            del utilisateurs[pseudo]
            print(f"[DÉCONNEXION] {pseudo} s'est totalement déconnecté (SID: {sid})")
            diffuser_liste_contacts()
        else:
            print(f"[RECONNEXION DUPLIQUÉE] Ancien SID nettoyé ({sid}) pour {pseudo}, la nouvelle session active est préservée.")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR MAXIMUM SECURITY HARDENED] Écoute active sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
