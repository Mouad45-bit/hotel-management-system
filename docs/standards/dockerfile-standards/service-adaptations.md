# Service-specific Dockerfile Adaptations

## Objective

This document explains which parts of the Dockerfile standard can vary by service.

The goal is to keep Dockerfiles consistent while still allowing each service to expose its own configuration.

## What can vary?

### Service port

Each service has its own port.

Examples:

```text
config-server → 8888
eureka-server → 8761
api-gateway   → 8080
auth-service  → 8081
room-service  → 8082
```

The standard Dockerfile supports this with:

```dockerfile
ARG SERVICE_PORT=8080
EXPOSE ${SERVICE_PORT}
```

### Docker image name

Each service has its own image name.

Examples:

```text
hms/config-server
hms/eureka-server
hms/api-gateway
hms/auth-service
hms/room-service
```

### Docker Compose environment variables

Each service can have specific environment variables.

Examples:

```yaml
environment:
  CONFIG_SERVER_PORT: 8888
```

```yaml
environment:
  SPRING_CONFIG_IMPORT: "configserver:http://config-server:8888"
  EUREKA_DEFAULT_ZONE: "http://eureka-server:8761/eureka/"
```

### Docker Compose healthcheck URL

Each service has a different healthcheck port.

Examples:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8888/actuator/health"]
```

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
```

### Maven dependencies

Dependencies can vary by service.

Examples:

- api-gateway uses Spring Cloud Gateway
- config-server uses Spring Cloud Config Server
- eureka-server uses Eureka Server
- business services use Spring Web, JPA, Validation and MariaDB driver

The Dockerfile does not need to change for this.

Maven dependencies belong in each service `pom.xml`.

## What must not vary?

The following rules must stay the same for every HMS Spring Boot service:

- use multi-stage Docker build
- use Maven builder stage
- use Java 17
- use lightweight runtime image
- install curl when healthchecks use curl
- use non-root `hotel` user
- copy the generated jar as `app.jar`
- start with `java -jar app.jar`

## Correct adaptation pattern

```text
Same Dockerfile structure
Different SERVICE_PORT
Different service pom.xml
Different docker-compose service block
```

## Incorrect adaptation pattern

```text
Different Java version per service
Running some services as root
Using Maven image as runtime image
Duplicating inconsistent Dockerfile logic
```

## Final rule

Only service-specific metadata and environment values should vary.

The Dockerfile structure must remain standardized.
