# Dockerfile Build Stage

## Objective

The build stage compiles the Spring Boot application and produces the executable jar.

## Standard image

```dockerfile
FROM maven:3.9.9-eclipse-temurin-17 AS builder
```

## Why this image?

This image contains:

- Maven
- JDK 17
- Eclipse Temurin Java distribution

It is used only to build the application.

It is not used as the final runtime image.

## Standard build stage

```dockerfile
FROM maven:3.9.9-eclipse-temurin-17 AS builder

WORKDIR /app

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn package -DskipTests -B
```

## Explanation

### WORKDIR /app

Defines `/app` as the working directory inside the image.

### COPY pom.xml .

Copies `pom.xml` first to improve Docker layer caching.

If only source files change, Docker can reuse the Maven dependency cache layer.

### RUN mvn dependency:go-offline -B

Downloads Maven dependencies before copying source code.

The `-B` option runs Maven in batch mode.

### COPY src ./src

Copies the application source code.

### RUN mvn package -DskipTests -B

Builds the Spring Boot jar.

Tests are skipped during Docker image build because tests are expected to run earlier in CI or during local validation.

## Final rule

Every HMS Spring Boot service must use a separated Maven build stage.
