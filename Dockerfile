# --- Étape 1 : compilation ---
FROM dart:stable AS build
WORKDIR /app 

COPY pubspec.yaml ./
RUN dart pub get

COPY . .
RUN dart pub get --offline
RUN dart compile exe bin/server.dart -o bin/server

# --- Étape 2 : image finale légère ---
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/bin/server /app/bin/server

# Render fournit la variable PORT, le serveur la lit déjà
EXPOSE 8080
CMD ["/app/bin/server"]
