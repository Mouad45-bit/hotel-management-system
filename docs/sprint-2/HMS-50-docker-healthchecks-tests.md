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

## Diagnostic commands

### Show all containers

```bash
docker compose ps
```

### Follow logs for one service

```bash
docker compose logs -f config-server
docker compose logs -f eureka-server
docker compose logs -f api-gateway
docker compose logs -f db-auth
```

### Show last logs only

```bash
docker compose logs --tail=100 api-gateway
```

### Inspect healthcheck status

```bash
docker inspect config-server --format '{{json .State.Health}}'
docker inspect eureka-server --format '{{json .State.Health}}'
docker inspect api-gateway --format '{{json .State.Health}}'
docker inspect db-auth --format '{{json .State.Health}}'
```

### Inspect healthcheck logs

```bash
docker inspect api-gateway --format '{{range .State.Health.Log}}{{.End}} {{.ExitCode}} {{.Output}}{{println}}{{end}}'
```

### Restart one service

```bash
docker compose restart api-gateway
```

### Rebuild one service

```bash
docker compose build api-gateway
docker compose up -d api-gateway
```

### Full clean restart

```bash
docker compose down
docker compose up --build -d
```

### Full clean restart with database volume deletion

Warning: this deletes local database data.

```bash
docker compose down -v
docker compose up --build -d
```
