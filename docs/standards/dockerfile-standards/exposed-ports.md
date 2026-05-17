# Exposed Ports Convention

## Objective

Each HMS microservice must expose its own HTTP port.

The Dockerfile should support service-specific ports without duplicating the entire Dockerfile logic.

## Standard Dockerfile rule

Use a build argument:

```dockerfile
ARG SERVICE_PORT=8080
EXPOSE ${SERVICE_PORT}
```

## Why use ARG?

`EXPOSE` must receive a valid port.

Using a variable like `808X` is useful in documentation but invalid for a real Docker build.

With `ARG SERVICE_PORT`, the same standard Dockerfile can be tested with different services.

## Port convention

| Service | Standard port |
|---|---:|
| config-server | 8888 |
| eureka-server | 8761 |
| api-gateway | 8080 |
| auth-service | 8081 |
| room-service | 8082 |
| client-service | 8083 |
| reservation-service | 8084 |
| billing-service | 8085 |
| housekeeping-service | 8086 |
| staff-service | 8087 |
| report-service | 8088 |

## Build examples

### config-server

```bash
docker build \
  -f docs/standards/dockerfile-standards/Dockerfile.standard \
  --build-arg SERVICE_PORT=8888 \
  -t hms/config-server:standard-test \
  ./config-server
```

### api-gateway

```bash
docker build \
  -f docs/standards/dockerfile-standards/Dockerfile.standard \
  --build-arg SERVICE_PORT=8080 \
  -t hms/api-gateway:standard-test \
  ./api-gateway
```

### future room-service

```bash
docker build \
  -f docs/standards/dockerfile-standards/Dockerfile.standard \
  --build-arg SERVICE_PORT=8082 \
  -t hms/room-service:standard-test \
  ./room-service
```

## Important note

`EXPOSE` is metadata.

It documents the container port, but it does not publish the port on the host.

Host publishing is done by Docker Compose:

```yaml
ports:
  - "8080:8080"
```

## Final rule

Every HMS Dockerfile must expose the service port through `ARG SERVICE_PORT`.
