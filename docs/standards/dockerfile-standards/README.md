# Dockerfile Standards

## Objective

This documentation defines the standard Dockerfile structure for HMS Spring Boot microservices.

The goal is to make every service containerized in a consistent, secure and maintainable way.

This standard applies to:

- config-server
- eureka-server
- api-gateway
- auth-service
- future business services

## Global Dockerfile rules

Every HMS Spring Boot microservice Dockerfile must:

- use a multi-stage build
- build the application with Maven and Java 17
- run the application with a lightweight Java 17 runtime image
- install curl when Docker healthchecks use curl
- create and use a non-root user
- expose the correct service port
- run the application with `java -jar app.jar`

## Documentation files

| File | Purpose |
|---|---|
| `Dockerfile.standard` | Final standard Dockerfile |
| `build-stage.md` | Maven build stage documentation |
| `runtime-stage.md` | Java 17 runtime stage documentation |
| `non-root-user.md` | Non-root user convention |
| `healthcheck-curl.md` | Curl and healthcheck convention |
| `exposed-ports.md` | Service port convention |
| `validation-existing-service.md` | Validation commands |
| `service-adaptations.md` | Allowed service-specific adaptations |

## Standard Dockerfile

```dockerfile
FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn package -DskipTests -B


FROM eclipse-temurin:17-jre-alpine

ARG SERVICE_PORT=8080

WORKDIR /app

RUN apk add --no-cache curl \
    && addgroup -S hotel \
    && adduser -S hotel -G hotel

COPY --from=builder /app/target/*.jar app.jar

RUN chown hotel:hotel app.jar

USER hotel

EXPOSE ${SERVICE_PORT}

ENTRYPOINT ["java", "-jar", "app.jar"]
```

## Why use a standard?

A standard Dockerfile helps:

- reduce duplicated decisions
- keep service images consistent
- simplify reviews
- improve container security
- make future services faster to create

## Final rule

Every HMS Spring Boot microservice must follow this Dockerfile standard unless a strong technical reason justifies an exception.
