import json
import os
import time
import eventlet
import socketio
import bcrypt

eventlet.monkey_patch()

sio = socketio.Server(cors_allowed_origins='*', async_mode='eventlet')
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"

# --- PROTECTION ANTI BRUTE-FORCE ---
tentatives_echouees = {}

def verifier_rate_limit(ip):
    maintenant = time.time()
    info = tentatives_echouees.get(ip, {'compteur': 0, 'bloque_jusqu_a': 0})
    if maintenant < info['bloque_jusqu_a']:
        temps_restant = int(info['bloque_jusqu_a'] - maintenant)
        return False, f"Trop d'échecs. Réessayez dans {temps_restant}s."
    return True, ""

def enregistrer_echec(ip):
    maintenant = time.time()
    info = tentatives_echouees.get(ip, {'compteur': 0, 'bloque_jusqu_a': 0})
    info['compteur'] += 1
    if info['compteur'] >= 5:
        info['bloque_jusqu_a'] = maintenant + 30
        info['compteur'] = 0
        print(f"[SECURITE] IP {ip} bloquée 30s.")
    tentatives_echouees[ip] = info

def reinitialiser_echecs(ip):
    if ip in tentatives_echouees:
        del tentatives_echouees[ip]

# --- GESTION DES COMPTES ---
def charger_comptes():
    if os.path.exists(FICHIER_COMPTES):
        try:
            with open(FICHIER_COMPTES, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def sauvegarder_comptes():
    try:
        with open(FICHIER_COMPTES, "w", encoding="utf-8") as f:
            json.dump(comptes, f, indent=4)
    except Exception as e:
        print(f"[ERREUR] Sauvegarde: {e}")

comptes = charger_comptes()
utilisateurs = {}  # { pseudo: sid }


@sio.event
def connect(sid, environ):
    ip = environ.get('REMOTE_ADDR', sid)
    print(f"[CONNEXION] IP: {ip} | SID: {sid}")


@sio.event
def enregistrer_utilisateur(sid, data):
    environ = sio.get_environ(sid)
    ip = environ.get('REMOTE_ADDR', sid) if environ else sid

    autorise, msg_erreur = verifier_rate_limit(ip)
    if not autorise:
        sio.emit('reponse_connexion', {'succes': False, 'message': msg_erreur}, room=sid)
        return

    pseudo = data.get('pseudo')
    code = data.get('code')

    if not pseudo or not code:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Champs requis."}, room=sid)
        return

    if pseudo not in comptes:
        sel = bcrypt.gensalt()
        comptes[pseudo] = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        sauvegarder_comptes()
        utilisateurs[pseudo] = sid
        reinitialiser_echecs(ip)
        print(f"[INSCRIPTION] Compte créé : '{pseudo}'.")
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Compte créé pour '{pseudo}'."}, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {'succes': False, 'message': "Déjà connecté."}, room=sid)
            return

        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            utilisateurs[pseudo] = sid
            reinitialiser_echecs(ip)
            print(f"[CONNEXION] Authentifié : '{pseudo}'.")
            sio.emit('reponse_connexion', {'succes': True, 'message': f"Bon retour, '{pseudo}' !"}, room=sid)
            sio.emit('liste_contacts', list(utilisateurs.keys()))
        else:
            enregistrer_echec(ip)
            sio.emit('reponse_connexion', {'succes': False, 'message': "Code incorrect !"}, room=sid)


@sio.event
def envoyer_message_direct(sid, data):
    destinataire = data.get('destinataire')
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
    print(f"[SERVEUR SÉCURISÉ] Démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
