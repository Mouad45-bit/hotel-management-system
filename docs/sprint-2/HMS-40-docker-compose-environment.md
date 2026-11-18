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

## Health checks

```bash
curl http://localhost:8888/actuator/health
curl http://localhost:8761/actuator/health
curl http://localhost:8080/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Eureka registration

```bash
curl http://localhost:8761/eureka/apps/API-GATEWAY
```

Expected result:

```text
API-GATEWAY is registered in Eureka.
```

## Docker network

```bash
docker network inspect hotel-network
```

Expected result:

```text
config-server
eureka-server
db-auth
api-gateway
```

## Auth service note

`auth-service` is not included yet because the module does not exist in the project yet.
It will be added to Docker Compose during the future Auth epic.
