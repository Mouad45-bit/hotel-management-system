# HMS-50 - Docker Healthchecks Tests

## Objective

Validate Docker healthchecks for available infrastructure services.

## Available services

- config-server
- eureka-server
- db-auth
- api-gateway

## Deferred service

auth-service is not implemented yet.

Its Docker healthcheck will be added during the future Auth epic when the service module exists.

## Start environment

```bash
docker compose down
docker compose up --build -d
```

## Check services status

```bash
docker compose ps
```

Expected result:

```text
config-server   healthy
eureka-server   healthy
db-auth         healthy
api-gateway     healthy
```

## Check config-server health

```bash
curl http://localhost:8888/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Check eureka-server health

```bash
curl http://localhost:8761/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Check api-gateway health

```bash
curl http://localhost:8080/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Check db-auth health from Docker

```bash
docker compose exec db-auth mariadb-admin ping -h localhost -uroot -p"${MYSQL_ROOT_PASSWORD:-root_hotel}" --silent
```

```text
mysqld is alive
```

## Test dependency order

```bash
docker compose down
docker compose up --build -d
docker compose ps
```

Expected result:

- eureka-server starts after config-server is healthy
- api-gateway starts after config-server and eureka-server are healthy

## Logs diagnostic

```bash
docker compose logs --tail=100 config-server
docker compose logs --tail=100 eureka-server
docker compose logs --tail=100 api-gateway
docker compose logs --tail=100 db-auth
```

## Conclusion

Docker healthchecks are configured and validated for the available infrastructure services.

`auth-service` healthcheck is deferred until the Auth epic.
