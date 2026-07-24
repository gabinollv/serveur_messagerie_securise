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
tentatives_echouees = {}  # { ip: {'compteur': int, 'bloque_jusqu_a': float} }

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
        info['bloque_jusqu_a'] = maintenant + 30  # Bloqué 30 secondes
        info['compteur'] = 0
        print(f"[SECURITE] IP {ip} bloquée 30s pour Brute-Force.")
    
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
        except Exception as e:
            print(f"[ERREUR] Lecture {FICHIER_COMPTES}: {e}")
            return {}
    return {}

def sauvegarder_comptes():
    try:
        with open(FICHIER_COMPTES, "w", encoding="utf-8") as f:
            json.dump(comptes, f, indent=4)
    except Exception as e:
        print(f"[ERREUR] Sauvegarde {FICHIER_COMPTES}: {e}")

comptes = charger_comptes()
utilisateurs = {}


@sio.event
def connect(sid, environ):
    ip = environ.get('REMOTE_ADDR', sid)
    print(f"[CONNEXION] IP: {ip} | SID: {sid}")


@sio.event
def enregistrer_utilisateur(sid, data):
    # Récupérer l'IP du client
    environ = sio.get_environ(sid)
    ip = environ.get('REMOTE_ADDR', sid) if environ else sid

    # Vérification Anti Brute-Force
    autorise, msg_erreur = verifier_rate_limit(ip)
    if not autorise:
        sio.emit('reponse_connexion', {'succes': False, 'message': msg_erreur}, room=sid)
        return

    pseudo = data.get('pseudo')
    code = data.get('code')

    if not pseudo or not code:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Pseudo et code obligatoires."}, room=sid)
        return

    # Inscription
    if pseudo not in comptes:
        sel = bcrypt.gensalt()
        code_hache = bcrypt.hashpw(code.encode('utf-8'), sel).decode('utf-8')
        comptes[pseudo] = code_hache
        sauvegarder_comptes()
        
        utilisateurs[pseudo] = sid
        reinitialiser_echecs(ip)
        print(f"[INSCRIPTION] Nouveau compte sécurisé pour '{pseudo}'.")
        sio.emit('reponse_connexion', {'succes': True, 'message': f"Bienvenue ! Compte créé pour '{pseudo}'."}, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))

    # Connexion
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {'succes': False, 'message': "Pseudo déjà connecté en ligne."}, room=sid)
            return

        if bcrypt.checkpw(code.encode('utf-8'), comptes[pseudo].encode('utf-8')):
            utilisateurs[pseudo] = sid
            reinitialiser_echecs(ip)
            print(f"[CONNEXION] '{pseudo}' authentifié.")
            sio.emit('reponse_connexion', {'succes': True, 'message': f"Bon retour, '{pseudo}' !"}, room=sid)
            sio.emit('liste_contacts', list(utilisateurs.keys()))
        else:
            enregistrer_echec(ip)
            print(f"[ÉCHEC] Mauvais code pour '{pseudo}'.")
            sio.emit('reponse_connexion', {'succes': False, 'message': "Code incorrect ou pseudo déjà pris !"}, room=sid)


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
    print(f"[SERVEUR] Démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
