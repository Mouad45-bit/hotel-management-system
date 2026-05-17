# Dockerfile Standard Validation

## Objective

This document explains how to validate the standard Dockerfile on existing HMS services.

The goal is to prove that the standard Dockerfile is realistic and usable.

## Services used for validation

Recommended existing services:

- config-server
- api-gateway

## Validate with config-server

Build image:

```bash
docker build \
  -f docs/standards/dockerfile-standards/Dockerfile.standard \
  --build-arg SERVICE_PORT=8888 \
  -t hms/config-server:standard-test \
  ./config-server
```

Run container:

```bash
docker run -d \
  --name config-server-standard-test \
  -p 8888:8888 \
  hms/config-server:standard-test
```

Verify health:

```bash
curl -f http://localhost:8888/actuator/health
```

Expected result:

```json
{
  "status": "UP"
}
```

Stop test container:

```bash
docker rm -f config-server-standard-test
```

## Validate non-root user

```bash
docker run --rm \
  --entrypoint whoami \
  hms/config-server:standard-test
```

Expected result:

```text
hotel
```

## Validate curl availability

```bash
docker run --rm \
  --entrypoint sh \
  hms/config-server:standard-test \
  -c "which curl"
```

Expected result:

```text
/usr/bin/curl
```

## Validate with api-gateway

Build image:

```bash
docker build \
  -f docs/standards/dockerfile-standards/Dockerfile.standard \
  --build-arg SERVICE_PORT=8080 \
  -t hms/api-gateway:standard-test \
  ./api-gateway
```

## Note about running api-gateway alone

The api-gateway usually depends on:

- config-server
- eureka-server

So building the image is enough for Dockerfile validation.

Full runtime validation should be done with Docker Compose.

## Cleanup test images

```bash
docker image rm hms/config-server:standard-test hms/api-gateway:standard-test
```

## Final rule

A standard Dockerfile is accepted only if it can build at least one existing HMS Spring Boot service.
