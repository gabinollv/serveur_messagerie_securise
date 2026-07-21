import os
import eventlet
import socketio

sio = socketio.Server(cors_allowed_origins='*')
app = socketio.WSGIApp(sio)

# Dictionnaire { pseudo: socket_id }
utilisateurs = {}


@sio.event
def connect(sid, environ):
    print(f"[CONNEXION] Client connecté : {sid}")


@sio.event
def enregistrer_utilisateur(sid, pseudo):
    utilisateurs[pseudo] = sid
    print(f"[ENREGISTREMENT] {pseudo} est connecté.")
    # Diffuser la liste mise à jour des contacts à tout le monde
    sio.emit('liste_contacts', list(utilisateurs.keys()))


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
    # Récupération du port dynamiquement attribué par Render (5000 par défaut en local)
    port = int(os.environ.get("PORT", 5000))
    print(f"[SERVEUR] Serveur de messagerie démarré sur le port {port}...")
    
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', port)), app)
