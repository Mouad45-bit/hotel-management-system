# Curl for Docker Healthchecks

## Objective

HMS runtime images must include `curl` when Docker healthchecks use HTTP health endpoints.

## Standard command

```dockerfile
RUN apk add --no-cache curl
```

In the HMS standard Dockerfile, this is combined with non-root user creation:

```dockerfile
RUN apk add --no-cache curl \
    && addgroup -S hotel \
    && adduser -S hotel -G hotel
```

## Why curl?

Docker Compose healthchecks usually validate Spring Boot health using:

```text
/actuator/health
```

Example:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
```

The `-f` option makes curl fail when the HTTP response is not successful.

## Why install curl in the runtime image?

The healthcheck command runs inside the container.

If the container does not contain curl, the healthcheck fails even if the application is healthy.

## Where should the healthcheck be defined?

The Dockerfile provides curl.

Docker Compose defines the actual healthcheck because each service has a different port.

Correct:

```text
Dockerfile → installs curl
docker-compose.yml → defines the healthcheck URL
```

## Final rule

If a service healthcheck uses curl, the runtime image must install curl.
