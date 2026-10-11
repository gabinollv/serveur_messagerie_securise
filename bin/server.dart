import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';

// ---------------------------------------------------------------------------
// Stockage : fichier users.json (clé = identifiant en minuscules)
// Pour un vrai projet, remplace par une base de données (PostgreSQL, SQLite...)
// ---------------------------------------------------------------------------
final File _usersFile = File('users.json');
Map<String, dynamic> _users = {};

// token -> identifiant (en mémoire : les sessions sont perdues au redémarrage)
final Map<String, String> _sessions = {};

void _loadUsers() {
  if (_usersFile.existsSync()) {
    _users = jsonDecode(_usersFile.readAsStringSync()) as Map<String, dynamic>;
  }
}

void _saveUsers() => _usersFile.writeAsStringSync(jsonEncode(_users));

// ---------------------------------------------------------------------------
// Sécurité : on ne stocke JAMAIS le mot de passe en clair
// ---------------------------------------------------------------------------
String _randomString(int bytes) {
  final rnd = Random.secure();
  return base64Url.encode(List<int>.generate(bytes, (_) => rnd.nextInt(256)));
}

String _hashPassword(String password, String salt) {
  var digest = utf8.encode('$salt$password');
  for (var i = 0; i < 10000; i++) {
    digest = sha256.convert([...digest, ...utf8.encode(salt)]).bytes;
  }
  return base64Url.encode(digest);
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
    return _json(400, {'error': 'Le mot de passe doit faire au moins 6 caractères'});
  }

  final key = identifiant.toLowerCase();
  if (_users.containsKey(key)) {
    return _json(409, {'error': 'Cet identifiant est déjà utilisé'});
  }

  final salt = _randomString(16);
  _users[key] = {
    'pseudo': pseudo,
    'identifiant': identifiant,
    'salt': salt,
    'passwordHash': _hashPassword(password, salt),
    'createdAt': DateTime.now().toIso8601String(),
  };
  _saveUsers();

  return _json(201, {'message': 'Compte créé avec succès'});
}

Future<Response> _login(Request req) async {
  final body = await _readBody(req);
  if (body == null) return _json(400, {'error': 'Requête invalide'});

  final pseudo = (body['pseudo'] ?? '').toString().trim();
  final identifiant = (body['identifiant'] ?? '').toString().trim();
  final password = (body['password'] ?? '').toString();

  final user = _users[identifiant.toLowerCase()] as Map<String, dynamic>?;
  const wrong = 'Pseudo, identifiant ou mot de passe incorrect';

  if (user == null) return _json(401, {'error': wrong});
  if (user['pseudo'] != pseudo) return _json(401, {'error': wrong});
  if (_hashPassword(password, user['salt'] as String) != user['passwordHash']) {
    return _json(401, {'error': wrong});
  }

  final token = _randomString(32);
  _sessions[token] = identifiant.toLowerCase();

  return _json(200, {
    'token': token,
    'user': {'pseudo': user['pseudo'], 'identifiant': user['identifiant']},
  });
}

Response _me(Request req) {
  final auth = req.headers['authorization'] ?? '';
  final token = auth.replaceFirst('Bearer ', '');
  final key = _sessions[token];
  if (key == null) return _json(401, {'error': 'Non connecté'});
  final user = _users[key] as Map<String, dynamic>;
  return _json(200, {'pseudo': user['pseudo'], 'identifiant': user['identifiant']});
}

void main() async {
  _loadUsers();

  final router = Router()
    ..get('/', (Request r) => _json(200, {'status': 'ok'}))
    ..post('/register', _register)
    ..post('/login', _login)
    ..get('/me', _me);

  final handler =
      const Pipeline().addMiddleware(logRequests()).addHandler(router.call);

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  print('Serveur démarré sur http://${server.address.host}:${server.port}');
}
