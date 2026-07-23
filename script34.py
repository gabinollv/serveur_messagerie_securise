import json
import os
import eventlet
import socketio

# Patch eventlet pour la gestion asynchrone
eventlet.monkey_patch()

sio = socketio.Server(cors_allowed_origins='*', async_mode='eventlet')
app = socketio.WSGIApp(sio)

# Nom du fichier où seront sauvegardés les comptes
FICHIER_COMPTES = "comptes.json"

# --- GESTION DE LA SAUVEGARDE DES COMPTES ---
def charger_comptes():
    """Charge les comptes depuis le fichier JSON s'il existe."""
    if os.path.exists(FICHIER_COMPTES):
        try:
            with open(FICHIER_COMPTES, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERREUR] Impossible de lire {FICHIER_COMPTES}: {e}")
            return {}
    return {}

def sauvegarder_comptes():
    """Sauvegarde le dictionnaire des comptes dans le fichier JSON."""
    try:
        with open(FICHIER_COMPTES, "w", encoding="utf-8") as f:
            json.dump(comptes, f, indent=4)
    except Exception as e:
        print(f"[ERREUR] Impossible de sauvegarder dans {FICHIER_COMPTES}: {e}")

# Chargement des comptes existants au démarrage du serveur
comptes = charger_comptes()
print(f"[SERVEUR] {len(comptes)} compte(s) chargé(s) depuis la base de données locale.")

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
        sauvegarder_comptes()  # 💾 Sauvegarde automatique du nouveau compte dans le fichier JSON !
        
        utilisateurs[pseudo] = sid
        print(f"[INSCRIPTION] Nouveau compte créé et sauvegardé pour '{pseudo}'.")
        sio.emit('reponse_connexion', {
            'succes': True, 
            'message': f"Bienvenue ! Compte créé avec succès pour '{pseudo}'."
        }, room=sid)
        sio.emit('liste_contacts', list(utilisateurs.keys()))

    # CAS 2 : Pseudo DÉJÀ EXISTANT -> AUTHENTIFICATION
    else:
        # Vérification 1 : Est-ce que le pseudo est déjà en ligne ?
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
            print(f"[ÉCHEC] Mauvais code pour le compte existant '{pseudo}'.")
            sio.emit('reponse_connexion', {
                'succes': False, 
                'message': "Ce pseudo appartient déjà à un autre utilisateur ! Mauvais code ou choisis un autre pseudo."
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
