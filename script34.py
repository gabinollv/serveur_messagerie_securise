import os
import eventlet
import socketio

sio = socketio.Server(cors_allowed_origins='*')
app = socketio.WSGIApp(sio)

# Dictionnaire des comptes inscrits : { pseudo: mot_de_passe }
comptes = {}

# Dictionnaire des sessions actives : { pseudo: socket_id }
utilisateurs = {}


@sio.event
def connect(sid, environ):
    print(f"[CONNEXION] Client connecté : {sid}")


@sio.event
def enregistrer_utilisateur(sid, data):
    # data contient : {'pseudo': 'Alice', 'code': '1234'}
    pseudo = data.get('pseudo')
    code = data.get('code')

    if not pseudo or not code:
        return {'succes': False, 'message': "Pseudo et code obligatoires."}

    # CAS 1 : Premier utilisateur -> Création du compte
    if pseudo not in comptes:
        comptes[pseudo] = code
        utilisateurs[pseudo] = sid
        print(f"[INSCRIPTION] Nouveau compte créé pour '{pseudo}'.")
        sio.emit('liste_contacts', list(utilisateurs.keys()))
        return {'succes': True, 'message': f"Bienvenue ! Compte créé pour '{pseudo}'."}

    # CAS 2 : Utilisateur existant -> Authentification
    else:
        # Vérification si le pseudo n'est pas DÉJÀ connecté
        if pseudo in utilisateurs:
            return {'succes': False, 'message': "Ce pseudo est déjà connecté actuellement."}

        # Vérification du mot de passe / code
        if comptes[pseudo] == code:
            utilisateurs[pseudo] = sid
            print(f"[CONNEXION] Authentification réussie pour '{pseudo}'.")
            sio.emit('liste_contacts', list(utilisateurs.keys()))
            return {'succes': True, 'message': f"Bon retour parmi nous, '{pseudo}' !"}
        else:
            print(f"[ÉCHEC] Mauvais code pour '{pseudo}'.")
            return {
                'succes': False,
                'message': "Ce pseudo est déjà réservé ! Mauvais code ou choisissez un autre pseudo."
            }


@sio.event
def envoyer_message_direct(sid, data):
    # data contient: {'destinataire': 'Bob', 'type': 'HANDSHAKE_INIT|HANDSHAKE_RESP|MSG', 'contenu': '...'}
    destinataire = data.get('destinataire')
    expediteur = data.get('expediteur')

    if destinataire in utilisateurs:
        target_sid = utilisateurs[destinataire]
        sio.emit('reception_message', data, room=target_sid)
        print(f"[RELAIS] Message ({data['type']}) de {expediteur} vers {destinataire}")


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
