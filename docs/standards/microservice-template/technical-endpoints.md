# Mandatory Technical Endpoints

## Objective

Each HMS microservice must expose a minimum set of technical endpoints.

These endpoints are used by:

- developers
- Docker healthchecks
- monitoring tools
- infrastructure services

## Required endpoint: /actuator/health

### URL

```text
GET /actuator/health
```

### Purpose

This endpoint indicates whether the service is running correctly.

It is used by Docker healthchecks and manual diagnostics.

### Expected response

```json
{
  "status": "UP"
}
```

### Required configuration

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

## Optional endpoint: /actuator/info

### URL

```text
GET /actuator/info
```

### Purpose

This endpoint can expose service metadata such as:

- service name
- version
- description
- build information

## Recommended healthcheck in Docker Compose

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:808X/actuator/health"]
  interval: 10s
  timeout: 5s
  retries: 10
  start_period: 40s
```

## Rule

Every service must expose `/actuator/health`.

A service without a health endpoint cannot be considered production-ready.
