import json
import os
import time
import tempfile
import eventlet
import socketio
import bcrypt

eventlet.monkey_patch()

# Configuration sécurisée SocketIO
MAX_MESSAGE_SIZE = 64 * 1024  # 64 KB max par message pour contrer les attaques DoS / RAM
sio = socketio.Server(
    cors_allowed_origins='*',
    async_mode='eventlet',
    max_http_buffer_size=MAX_MESSAGE_SIZE
)
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"
tentatives_echouees = {}

def verifier_rate_limit(ip):
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
        info['bloque_jusqu_a'] = maintenant + 30
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
            print(f"[ERREUR CRITIQUE] Lecture comptes.json: {e}")
            return {}
    return {}

def sauvegarder_comptes_atomique():
    """Sauvegarde atomique pour éviter la corruption du fichier lors d'inscriptions simultanées."""
    try:
        dir_name = os.path.dirname(FICHIER_COMPTES) or '.'
        with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name, encoding='utf-8') as tf:
            json.dump(comptes, tf, indent=4)
            temp_name = tf.name
        os.replace(temp_name, FICHIER_COMPTES)
    except Exception as e:
        print(f"[ERREUR CRITIQUE] Sauvegarde atomique : {e}")

comptes = charger_comptes()
utilisateurs = {}

@sio.event
def connect(sid, environ):
    pass

@sio.event
def enregistrer_utilisateur(sid, data):
    if not isinstance(data, dict):
        return

    environ = sio.get_environ(sid)
    ip = environ.get('HTTP_X_FORWARDED_FOR', environ.get('REMOTE_ADDR', sid)).split(',')[0].strip() if environ else sid

    autorise, msg_erreur = verifier_rate_limit(ip)
    if not autorise:
        sio.emit('reponse_connexion', {'succes': False, 'message': msg_erreur}, room=sid)
        return

    pseudo = str(data.get('pseudo', '')).strip()
    code = str(data.get('code', '')).strip()

    # Validation et nettoyage strict des entrées (Input Sanitization)
    if not pseudo or not code or len(pseudo) > 64 or len(code) > 64:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Pseudo/Code invalide (max 64 caractères)."}, room=sid)
        return

    if pseudo not in comptes:
        sel = bcrypt.gensalt(rounds=12)
        comptes[pseudo] = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        sauvegarder_comptes_atomique()
        utilisateurs[pseudo] = sid
        reinitialiser_echecs(ip)
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte créé pour '{pseudo}'."}, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {'succes': False, 'message': "Déjà connecté ailleurs."}, room=sid)
            return

        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            utilisateurs[pseudo] = sid
            reinitialiser_echecs(ip)
            sio.emit('reponse_connexion', {'succes': True, 'message': f"Bon retour, '{pseudo}' !"}, room=sid)
            sio.emit('liste_contacts', list(utilisateurs.keys()))
        else:
            enregistrer_echec(ip)
            sio.emit('reponse_connexion', {'succes': False, 'message': "Code incorrect !"}, room=sid)

@sio.event
def envoyer_message_direct(sid, data):
    if not isinstance(data, dict):
        return
    
    destinataire = str(data.get('destinataire', ''))
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('reception_message', data, room=target_sid)

@sio.event
def disconnect(sid):
    for pseudo, s_id in list(utilisateurs.items()):
        if s_id == sid:
            del utilisateurs[pseudo]
            sio.emit('liste_contacts', list(utilisateurs.keys()))
            break

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR SÉCURISÉ HARDENED] Démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
