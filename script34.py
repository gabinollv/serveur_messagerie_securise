import os
import eventlet
import socketio

# Patch eventlet pour gérer les entrées/sorties de manière asynchrone
eventlet.monkey_patch()

sio = socketio.Server(cors_allowed_origins='*', async_mode='eventlet')
app = socketio.WSGIApp(sio)

# Dictionnaire des comptes inscrits : { pseudo: code }
comptes = {}

# Dictionnaire des sessions actives : { pseudo: socket_id }
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

    # CAS 1 : Pseudo jamais utilisé -> CRÉATION DU COMPTE UNIQUE
    if pseudo not in comptes:
        comptes[pseudo] = code
        utilisateurs[pseudo] = sid
        print(f"[INSCRIPTION] Compte créé pour '{pseudo}'.")
        sio.emit('reponse_connexion', {
            'succes': True, 
            'message': f"Bienvenue ! Compte créé avec succès pour '{pseudo}'."
        }, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))

    # CAS 2 : Pseudo DÉJÀ EXIETANT -> AUTHENTIFICATION
    else:
        # Vérification 1 : Est-ce que le pseudo est déjà en cours d'utilisation ?
        if pseudo in utilisateurs:
            sio.emit('reponse_connexion', {
                'succes': False, 
                'message': "Ce pseudo est déjà en ligne sur un autre appareil."
            }, room=sid)
            return

        # Vérification 2 : Est-ce que le code correspond au compte d'origine ?
        if comptes[pseudo] == code:
            utilisateurs[pseudo] = sid
            print(f"[CONNEXION] Authentification réussie pour '{pseudo}'.")
            sio.emit('reponse_connexion', {
                'succes': True, 
                'message': f"Bon retour parmi nous, '{pseudo}' !"
            }, room=sid)
            sio.emit('liste_contacts', list(utilisateurs.keys()))
        else:
            # Le pseudo existe déjà ET le code est faux -> Tentative d'usurpation
            print(f"[ÉCHEC] Tentative de connexion avec un mauvais code sur '{pseudo}'.")
            sio.emit('reponse_connexion', {
                'succes': False, 
                'message': "Ce pseudo appartient déjà à un autre utilisateur ! Choisis un autre pseudo."
            }, room=sid)


@sio.event
def envoyer_message_direct(sid, data):
    destinataire = data.get('destinataire')
    expediteur = data.get('expediteur')

    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('reception_message', data, room=target_sid)
        print(f"[RELAIS] Message ({data.get('type')}) de {expediteur} vers {destinataire}")


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
    print(f"[SERVEUR] Serveur de messagerie démarré sur le port {port}...")
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
