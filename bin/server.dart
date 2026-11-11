import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:postgres/postgres.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';

// ---------------------------------------------------------------------------
// Base de données PostgreSQL (Neon) : l'adresse est dans la variable
// d'environnement DATABASE_URL, définie sur Render (jamais dans le code !)
// ---------------------------------------------------------------------------
late final Pool _db;

Pool _connect() {
  final url = Platform.environment['DATABASE_URL'];
  if (url == null || url.isEmpty) {
    stderr.writeln('Variable DATABASE_URL manquante');
    exit(1);
  }
  final uri = Uri.parse(url);
  final info = uri.userInfo.split(':');
  final endpoint = Endpoint(
    host: uri.host,
    port: uri.hasPort ? uri.port : 5432,
    database: uri.path.replaceFirst('/', ''),
    username: Uri.decodeComponent(info[0]),
    password:
        info.length > 1 ? Uri.decodeComponent(info.sublist(1).join(':')) : null,
  );
  return Pool.withEndpoints(
    [endpoint],
    settings: PoolSettings(maxConnectionCount: 5, sslMode: SslMode.require),
  );
}

Future<void> _initDb() async {
  await _db.execute('''
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      pseudo TEXT NOT NULL,
      identifiant TEXT NOT NULL,
      identifiant_key TEXT NOT NULL UNIQUE,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  ''');
  // Migration : les comptes existants gardent l'ancien algorithme jusqu'à
  // leur prochaine connexion, où ils sont automatiquement migrés vers Argon2id.
  await _db.execute(
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS hash_algo TEXT NOT NULL "
    "DEFAULT '$_legacyAlgo'",
  );
  await _db.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  ''');
  await _db.execute(
    'CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)',
  );
}

// ---------------------------------------------------------------------------
// Sécurité : on ne stocke JAMAIS le mot de passe ni le token en clair
// ---------------------------------------------------------------------------
const _legacyAlgo = 'sha256-legacy';
// Argon2id, paramètres OWASP : 19 Mio de mémoire, 2 itérations, 1 thread.
// Si tu changes les paramètres, crée un nouveau nom (ex. 'argon2id-v2') :
// les comptes seront migrés automatiquement à leur prochaine connexion.
const _argonAlgo = 'argon2id-v1';

String _randomString(int bytes) {
  final rnd = Random.secure();
  return base64Url.encode(List<int>.generate(bytes, (_) => rnd.nextInt(256)));
}

// Ancien hachage, conservé uniquement pour vérifier les comptes non migrés.
String _legacyHash(String password, String salt) {
  List<int> digest = utf8.encode('$salt$password');
  for (var i = 0; i < 10000; i++) {
    digest =
        crypto.sha256.convert([...digest, ...utf8.encode(salt)]).bytes;
  }
  return base64Url.encode(digest);
}

Future<String> _computeHash(String password, String salt, String algo) async {
  if (algo == _legacyAlgo) return _legacyHash(password, salt);
  final argon2 = cg.Argon2id(
    memory: 19456,
    parallelism: 1,
    iterations: 2,
    hashLength: 32,
  );
  final key = await argon2.deriveKeyFromPassword(
    password: password,
    nonce: base64Url.decode(salt),
  );
  return base64Url.encode(await key.extractBytes());
}

// Le calcul tourne dans un isolate séparé pour ne pas bloquer le serveur
// pendant qu'il hache un mot de passe.
Future<String> _hashPassword(String password, String salt, String algo) =>
    Isolate.run(() => _computeHash(password, salt, algo));

// Comparaison en temps constant (évite de révéler le hash par le temps de réponse)
bool _safeEquals(String a, String b) {
  final x = utf8.encode(a);
  final y = utf8.encode(b);
  var diff = x.length ^ y.length;
  for (var i = 0; i < min(x.length, y.length); i++) {
    diff |= x[i] ^ y[i];
  }
  return diff == 0;
}

String _hashToken(String token) =>
    crypto.sha256.convert(utf8.encode(token)).toString();

String _bearer(Request req) {
  final header = req.headers['authorization'] ?? '';
  return header.startsWith('Bearer ') ? header.substring(7).trim() : '';
}

Response _json(int status, Map<String, dynamic> body) => Response(
      status,
      body: jsonEncode(body),
      headers: {'content-type': 'application/json; charset=utf-8'},
    );

Future<Map<String, dynamic>?> _readBody(Request req) async {
  try {
    final data = jsonDecode(await req.readAsString());
    return data is Map<String, dynamic> ? data : null;
  } catch (_) {
    return null;
  }
}

// Évite qu'une erreur de base de données fasse planter le serveur
Middleware _catchErrors() => (inner) => (req) async {
      try {
        return await inner(req);
      } catch (e, st) {
        stderr.writeln('Erreur : $e\n$st');
        return _json(500, {'error': 'Erreur interne du serveur'});
      }
    };

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
Future<Response> _register(Request req) async {
  final body = await _readBody(req);
  if (body == null) return _json(400, {'error': 'Requête invalide'});

  final pseudo = (body['pseudo'] ?? '').toString().trim();
  final identifiant = (body['identifiant'] ?? '').toString().trim();
  final password = (body['password'] ?? '').toString();

  if (pseudo.isEmpty || identifiant.isEmpty || password.isEmpty) {
    return _json(400, {'error': 'Tous les champs sont obligatoires'});
  }
  if (password.length < 6) {
    return _json(
        400, {'error': 'Le mot de passe doit faire au moins 6 caractères'});
  }

  final salt = _randomString(16);
  final hash = await _hashPassword(password, salt, _argonAlgo);
  try {
    await _db.execute(
      Sql.named('INSERT INTO users (pseudo, identifiant, identifiant_key, '
          'salt, password_hash, hash_algo) '
          'VALUES (@pseudo, @identifiant, @key, @salt, @hash, @algo)'),
      parameters: {
        'pseudo': pseudo,
        'identifiant': identifiant,
        'key': identifiant.toLowerCase(),
        'salt': salt,
        'hash': hash,
        'algo': _argonAlgo,
      },
    );
  } on ServerException catch (e) {
    if (e.code == '23505') {
      return _json(409, {'error': 'Cet identifiant est déjà utilisé'});
    }
    rethrow;
  }

  return _json(201, {'message': 'Compte créé avec succès'});
}

// Sel factice : sert à hacher quand l'identifiant n'existe pas, pour que la
// réponse prenne le même temps (on ne révèle pas quels identifiants existent).
final _dummySalt = _randomString(16);

Future<Response> _login(Request req) async {
  final body = await _readBody(req);
  if (body == null) return _json(400, {'error': 'Requête invalide'});

  final pseudo = (body['pseudo'] ?? '').toString().trim();
  final identifiant = (body['identifiant'] ?? '').toString().trim();
  final password = (body['password'] ?? '').toString();
  const wrong = 'Pseudo, identifiant ou mot de passe incorrect';

  final res = await _db.execute(
    Sql.named('SELECT * FROM users WHERE identifiant_key = @key'),
    parameters: {'key': identifiant.toLowerCase()},
  );
  if (res.isEmpty) {
    await _hashPassword(password, _dummySalt, _argonAlgo);
    return _json(401, {'error': wrong});
  }

  final user = res.first.toColumnMap();
  final algo = user['hash_algo'] as String;
  final computed =
      await _hashPassword(password, user['salt'] as String, algo);
  final passwordOk = _safeEquals(computed, user['password_hash'] as String);
  if (!passwordOk || user['pseudo'] != pseudo) {
    return _json(401, {'error': wrong});
  }

  // Migration transparente : un ancien compte passe à Argon2id maintenant
  // que l'on connaît son mot de passe en clair.
  if (algo != _argonAlgo) {
    final newSalt = _randomString(16);
    await _db.execute(
      Sql.named('UPDATE users SET salt = @salt, password_hash = @hash, '
          'hash_algo = @algo WHERE id = @id'),
      parameters: {
        'salt': newSalt,
        'hash': await _hashPassword(password, newSalt, _argonAlgo),
        'algo': _argonAlgo,
        'id': user['id'],
      },
    );
  }

  final token = _randomString(32);
  await _db.execute(
    Sql.named('INSERT INTO sessions (token_hash, user_id) VALUES (@t, @u)'),
    parameters: {'t': _hashToken(token), 'u': user['id']},
  );

  return _json(200, {
    'token': token,
    'user': {
      'id': user['id'],
      'pseudo': user['pseudo'],
      'identifiant': user['identifiant'],
    },
  });
}

// Les sessions n'expirent pas : un token reste valide jusqu'à /logout
// ou /logout_all.
Future<Response> _me(Request req) async {
  final token = _bearer(req);
  if (token.isEmpty) return _json(401, {'error': 'Non connecté'});

  final res = await _db.execute(
    Sql.named('SELECT u.id, u.pseudo, u.identifiant FROM sessions s '
        'JOIN users u ON u.id = s.user_id WHERE s.token_hash = @t'),
    parameters: {'t': _hashToken(token)},
  );
  if (res.isEmpty) return _json(401, {'error': 'Session invalide'});

  final user = res.first.toColumnMap();
  return _json(200, {
    'id': user['id'],
    'pseudo': user['pseudo'],
    'identifiant': user['identifiant'],
  });
}

// Déconnecte cet appareil : supprime la session du token envoyé.
Future<Response> _logout(Request req) async {
  final token = _bearer(req);
  if (token.isEmpty) return _json(401, {'error': 'Non connecté'});

  await _db.execute(
    Sql.named('DELETE FROM sessions WHERE token_hash = @t'),
    parameters: {'t': _hashToken(token)},
  );
  return _json(200, {'message': 'Déconnecté'});
}

// Déconnecte tous les appareils du compte (utile si un token est volé).
Future<Response> _logoutAll(Request req) async {
  final token = _bearer(req);
  if (token.isEmpty) return _json(401, {'error': 'Non connecté'});

  final res = await _db.execute(
    Sql.named('DELETE FROM sessions WHERE user_id = '
        '(SELECT user_id FROM sessions WHERE token_hash = @t)'),
    parameters: {'t': _hashToken(token)},
  );
  if (res.affectedRows == 0) return _json(401, {'error': 'Session invalide'});
  return _json(200, {'message': 'Tous les appareils sont déconnectés'});
}

void main() async {
  _db = _connect();
  await _initDb();

  final router = Router()
    ..get('/', (Request r) => _json(200, {'status': 'ok'}))
    ..post('/register', _register)
    ..post('/login', _login)
    ..get('/me', _me)
    ..post('/logout', _logout)
    ..post('/logout_all', _logoutAll);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(_catchErrors())
      .addHandler(router.call);

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  print('Serveur démarré sur le port ${server.port}');
}
