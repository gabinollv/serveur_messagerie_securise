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
        # Blocage progressif : 60 secondes
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
    # On renvoie l'ensemble des comptes inscrits
    liste_membres = list(comptes.keys())
    sio.emit('liste_contacts', liste_membres)

@sio.event
def connect(sid, environ):
    pass

@sio.event
def enregistrer_utilisateur(sid, data):
    if not isinstance(data, dict):
        return

    environ = sio.get_environ(sid)
    # Isolation stricte de l'adresse IP distante
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
        # Hachage fort Bcrypt (Work Factor 12)
        sel = bcrypt.gensalt(rounds=12)
        comptes[pseudo] = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        sauvegarder_comptes_atomique()
        
        utilisateurs[pseudo] = sid
        sid_vers_pseudo[sid] = pseudo
        reinitialiser_echecs(ip)
        
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte sécurisé créé pour '{pseudo}'."}, room=sid)
        diffuser_liste_contacts()
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {'succes': False, 'message': "Session déjà active pour cet utilisateur."}, room=sid)
            return

        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            utilisateurs[pseudo] = sid
            sid_vers_pseudo[sid] = pseudo
            reinitialiser_echecs(ip)
            
            sio.emit('reponse_connexion', {'succes': True, 'message': f"Authentifié en tant que '{pseudo}'."}, room=sid)
            diffuser_liste_contacts()
        else:
            enregistrer_echec(ip)
            sio.emit('reponse_connexion', {'succes': False, 'message': "Identifiants invalides !"}, room=sid)

@sio.event
def obtenir_liste_contacts(sid, data=None):
    """Permet au client de redemander la liste des membres à tout moment."""
    sio.emit('liste_contacts', list(comptes.keys()), room=sid)

@sio.event
def envoyer_demande_ami(sid, data):
    """Relaye une demande d'ami vers le destinataire ciblé."""
    if not isinstance(data, dict):
        return
    
    demandeur = sid_vers_pseudo.get(sid)
    if not demandeur:
        return

    destinataire = str(data.get('destinataire', '')).strip()
    
    # Si le destinataire est connecté, on lui transmet la demande en direct
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('demande_ami_recue', {'demandeur': demandeur}, room=target_sid)

@sio.event
def reponse_demande_ami(sid, data):
    """Relaye la réponse (acceptée/refusée) à l'initiateur de la demande."""
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
        return
    
    # Validation du SID et élimination de l'usurpation d'identité
    expediteur_reel = sid_vers_pseudo.get(sid)
    if not expediteur_reel:
        return

    destinataire = str(data.get('destinataire', ''))
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        
        # Reconstruction stricte du payload sur le serveur avant relais
        payload_securise = {
            'expediteur': expediteur_reel,
            'destinataire': destinataire,
            'type': str(data.get('type', '')),
            'contenu': str(data.get('contenu', '')),
            'signature': str(data.get('signature', ''))
        }
        sio.emit('reception_message', payload_securise, room=target_sid)

@sio.event
def disconnect(sid):
    if sid in sid_vers_pseudo:
        pseudo = sid_vers_pseudo.pop(sid)
        if pseudo in utilisateurs:
            del utilisateurs[pseudo]
        diffuser_liste_contacts()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR MAXIMUM SECURITY HARDENED] Écoute active sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
