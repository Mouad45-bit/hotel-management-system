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

## Final standard Dockerfile

The final standard Dockerfile is documented in:

```text
docs/standards/dockerfile-standards/Dockerfile.standard
```

## Why use a standard?

A standard Dockerfile helps:

- reduce duplicated decisions
- keep service images consistent
- simplify reviews
- improve container security
- make future services faster to create
