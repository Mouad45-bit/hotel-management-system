# Dockerfile Runtime Stage

## Objective

The runtime stage contains only what is needed to run the Spring Boot application.

It must not contain Maven or build tools.

## Standard image

```dockerfile
FROM eclipse-temurin:17-jre-alpine
```

## Why this image?

This image contains:

- Java 17 runtime
- Alpine Linux base
- smaller runtime footprint than a full JDK image

## Standard runtime stage

```dockerfile
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

## Explanation

### COPY --from=builder

Copies only the generated jar from the build stage.

The final image does not keep:

- source code
- Maven cache
- Maven installation
- build-time files

### ENTRYPOINT

The service starts with:

```dockerfile
ENTRYPOINT ["java", "-jar", "app.jar"]
```

This is the standard way to run a Spring Boot executable jar.

## Final rule

The runtime stage must use Java 17 and must not include Maven.
