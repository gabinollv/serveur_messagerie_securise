import json
import os
import time
import tempfile
import eventlet
import socketio
import bcrypt

eventlet.monkey_patch()

MAX_MESSAGE_SIZE = 64 * 1024  # 64 KB max
sio = socketio.Server(
    cors_allowed_origins='*',
    async_mode='eventlet',
    max_http_buffer_size=MAX_MESSAGE_SIZE
)
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"
tentatives_echouees = {}

utilisateurs = {}       # { pseudo: sid }
sid_vers_pseudo = {}    # { sid: pseudo }

def nettoyer_rate_limit():
    """Nettoyage périodique pour éviter la fuite de mémoire (DoS)."""
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
    try:
        dir_name = os.path.dirname(FICHIER_COMPTES) or '.'
        with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name, encoding='utf-8') as tf:
            json.dump(comptes, tf, indent=4)
            temp_name = tf.name
        os.replace(temp_name, FICHIER_COMPTES)
    except Exception as e:
        print(f"[ERREUR CRITIQUE] Sauvegarde atomique : {e}")

comptes = charger_comptes()

@sio.event
def connect(sid, environ):
    pass

@sio.event
def enregistrer_utilisateur(sid, data):
    if not isinstance(data, dict):
        return

    environ = sio.get_environ(sid)
    # FIX FAILLES #2 : Pas de X-Forwarded-For non filtré
    ip = environ.get('REMOTE_ADDR', sid) if environ else sid

    autorise, msg_erreur = verifier_rate_limit(ip)
    if not autorise:
        sio.emit('reponse_connexion', {'succes': False, 'message': msg_erreur}, room=sid)
        return

    pseudo = str(data.get('pseudo', '')).strip()
    code = str(data.get('code', '')).strip()

    if not pseudo or not code or len(pseudo) > 64 or len(code) > 64:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Pseudo/Code invalide."}, room=sid)
        return

    if pseudo not in comptes:
        sel = bcrypt.gensalt(rounds=12)
        comptes[pseudo] = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        sauvegarder_comptes_atomique()
        
        utilisateurs[pseudo] = sid
        sid_vers_pseudo[sid] = pseudo
        reinitialiser_echecs(ip)
        
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte créé pour '{pseudo}'."}, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {'succes': False, 'message': "Déjà connecté ailleurs."}, room=sid)
            return

        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            utilisateurs[pseudo] = sid
            sid_vers_pseudo[sid] = pseudo
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
    
    # FIX FAILLE #1 : Détermination explicite de l'expéditeur via le SID
    expediteur_reel = sid_vers_pseudo.get(sid)
    if not expediteur_reel:
        return

    destinataire = str(data.get('destinataire', ''))
    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        
        payload_securise = {
            'expediteur': expediteur_reel,
            'destinataire': destinataire,
            'type': data.get('type'),
            'contenu': data.get('contenu'),
            'signature': data.get('signature')
        }
        sio.emit('reception_message', payload_securise, room=target_sid)

@sio.event
def disconnect(sid):
    if sid in sid_vers_pseudo:
        pseudo = sid_vers_pseudo.pop(sid)
        if pseudo in utilisateurs:
            del utilisateurs[pseudo]
        sio.emit('liste_contacts', list(utilisateurs.keys()))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR SÉCURISÉ HARDENED] Démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
