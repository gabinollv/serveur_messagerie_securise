import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
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
  await _db.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  ''');
}

// ---------------------------------------------------------------------------
// Sécurité : on ne stocke JAMAIS le mot de passe ni le token en clair
// ---------------------------------------------------------------------------
String _randomString(int bytes) {
  final rnd = Random.secure();
  return base64Url.encode(List<int>.generate(bytes, (_) => rnd.nextInt(256)));
}

String _hashPassword(String password, String salt) {
  List<int> digest = utf8.encode('$salt$password');
  for (var i = 0; i < 10000; i++) {
    digest = sha256.convert([...digest, ...utf8.encode(salt)]).bytes;
  }
  return base64Url.encode(digest);
}

String _hashToken(String token) => sha256.convert(utf8.encode(token)).toString();

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
  try {
    await _db.execute(
      Sql.named('INSERT INTO users (pseudo, identifiant, identifiant_key, '
          'salt, password_hash) VALUES (@pseudo, @identifiant, @key, @salt, @hash)'),
      parameters: {
        'pseudo': pseudo,
        'identifiant': identifiant,
        'key': identifiant.toLowerCase(),
        'salt': salt,
        'hash': _hashPassword(password, salt),
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
  if (res.isEmpty) return _json(401, {'error': wrong});

  final user = res.first.toColumnMap();
  if (user['pseudo'] != pseudo) return _json(401, {'error': wrong});
  if (_hashPassword(password, user['salt'] as String) !=
      user['password_hash']) {
    return _json(401, {'error': wrong});
  }

  final token = _randomString(32);
  await _db.execute(
    Sql.named('INSERT INTO sessions (token_hash, user_id) VALUES (@t, @u)'),
    parameters: {'t': _hashToken(token), 'u': user['id']},
  );

  return _json(200, {
    'token': token,
    'user': {'pseudo': user['pseudo'], 'identifiant': user['identifiant']},
  });
}

Future<Response> _me(Request req) async {
  final token = (req.headers['authorization'] ?? '').replaceFirst('Bearer ', '');
  if (token.isEmpty) return _json(401, {'error': 'Non connecté'});

  final res = await _db.execute(
    Sql.named('SELECT u.pseudo, u.identifiant FROM sessions s '
        'JOIN users u ON u.id = s.user_id '
        "WHERE s.token_hash = @t AND s.created_at > now() - interval '30 days'"),
    parameters: {'t': _hashToken(token)},
  );
  if (res.isEmpty) return _json(401, {'error': 'Session expirée'});

  final user = res.first.toColumnMap();
  return _json(200, {'pseudo': user['pseudo'], 'identifiant': user['identifiant']});
}

void main() async {
  _db = _connect();
  await _initDb();

  final router = Router()
    ..get('/', (Request r) => _json(200, {'status': 'ok'}))
    ..post('/register', _register)
    ..post('/login', _login)
    ..get('/me', _me);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(_catchErrors())
      .addHandler(router.call);

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  print('Serveur démarré sur le port ${server.port}');
}
