import json
import os
import eventlet
import socketio
import bcrypt

# Patch eventlet pour la gestion asynchrone
eventlet.monkey_patch()

sio = socketio.Server(cors_allowed_origins='*', async_mode='eventlet')
app = socketio.WSGIApp(sio)

FICHIER_COMPTES = "comptes.json"

def charger_comptes():
    if os.path.exists(FICHIER_COMPTES):
        try:
            with open(FICHIER_COMPTES, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERREUR] Impossible de lire {FICHIER_COMPTES}: {e}")
            return {}
    return {}

def sauvegarder_comptes():
    try:
        with open(FICHIER_COMPTES, "w", encoding="utf-8") as f:
            json.dump(comptes, f, indent=4)
    except Exception as e:
        print(f"[ERREUR] Impossible de sauvegarder dans {FICHIER_COMPTES}: {e}")

comptes = charger_comptes()
print(f"[SERVEUR] {len(comptes)} compte(s) chargé(s) depuis la base de données locale.")

utilisateurs = {}

@sio.event
def connect(sid, environ):
    print(f"[CONNEXION] Client connecté : {sid}")

@sio.event
def enregistrer_utilisateur(sid, data):
    pseudo = data.get('pseudo')
    code = data.get('code')

    if not pseudo or not code:
        sio.emit('reponse_connexion', {'succes': False, 'message': "Pseudo et code obligatoires."}, room=sid)
        return

    # CAS 1 : Inscription -> On HACHE le code avant de le stocker !
    if pseudo not in comptes:
        # Génération du sel + hachage
        code_bytes = code.encode('utf-8')
        sel = bcrypt.gensalt()
        code_hache = bcrypt.hashpw(code_bytes, sel).decode('utf-8')

        comptes[pseudo] = code_hache
        sauvegarder_comptes()
        
        utilisateurs[pseudo] = sid
        print(f"[INSCRIPTION SÉCURISÉE] Compte créé et code haché pour '{pseudo}'.")
        sio.emit('reponse_connexion', {
            'succes': True, 
            'message': f"Bienvenue ! Compte créé avec succès pour '{pseudo}'."
        }, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))

    # CAS 2 : Connexion -> On vérifie le hachage
    else:
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {
                'succes': False, 
                'message': "Ce pseudo est déjà en ligne sur un autre appareil."
            }, room=sid)
            return

        # Vérification sécurisée du mot de passe haché
        code_bytes = code.encode('utf-8')
        code_hache_enregistre = comptes[pseudo].encode('utf-8')

        if bcrypt.checkpw(code_bytes, code_hache_enregistre):
            utilisateurs[pseudo] = sid
            print(f"[CONNEXION] Authentification réussie pour '{pseudo}'.")
            sio.emit('reponse_connexion', {
                'succes': True, 
                'message': f"Bon retour parmi nous, '{pseudo}' !"
            }, room=sid)
            sio.emit('liste_contacts', list(utilisateurs.keys()))
        else:
            print(f"[ÉCHEC] Mauvais code pour '{pseudo}'.")
            sio.emit('reponse_connexion', {
                'succes': False, 
                'message': "Ce pseudo appartient déjà à un autre utilisateur ! Mauvais code."
            }, room=sid)

@sio.event
def envoyer_message_direct(sid, data):
    destinataire = data.get('destinataire')
    expediteur = data.get('expediteur')

    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('reception_message', data, room=target_sid)
        print(f"[RELAIS] Message de {expediteur} vers {destinataire}")

@sio.event
def disconnect(sid):
    for pseudo, s_id in list(utilisateurs.items()):
        if s_id == sid:
            del utilisateurs[pseudo]
            print(f"[DÉCONNEXION] {pseudo} s'est déconnecté.")
            sio.emit('liste_contacts', list(utilisateurs.keys()))
            break

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR] Serveur démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
