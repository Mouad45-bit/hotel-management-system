# HMS-40 - Docker Compose Environment

## Objective

Start the available infrastructure services with one Docker Compose command.

## Available services in the clean project restart

- config-server
- eureka-server
- db-auth
- api-gateway

## Deferred service

`auth-service` is intentionally not added to `docker-compose.yml` in this story.

Reason:

The `auth-service` module is not implemented yet in the clean project restart.

Adding this service now would break:

```bash
docker compose up --build
```

because Docker Compose would try to build a non-existing `./auth-service` directory.

The service will be added later in the Auth epic when the module exists.

## Expected command

```bash
docker compose up --build -d
```

## Expected result

```text
config-server   running / healthy
eureka-server   running / healthy
db-auth         running / healthy
api-gateway     running / healthy
```
