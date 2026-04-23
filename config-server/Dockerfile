# ── Stage 1 : build Maven ───────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app

# Copier le pom en premier pour bénéficier du cache des dépendances Maven
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copier les sources et compiler (sans tests)
COPY src ./src
RUN mvn package -DskipTests -B

# ── Stage 2 : image runtime légère ──────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Créer un utilisateur non-root pour la sécurité
RUN addgroup -S hotel && adduser -S hotel -G hotel

COPY --from=builder /app/target/*.jar app.jar
RUN chown hotel:hotel app.jar

USER hotel
EXPOSE 8888

ENTRYPOINT ["java", "-jar", "app.jar"]