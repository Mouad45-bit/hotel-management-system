# HMS-31 - Centralized YAML Configuration Tests

## Objective

Validate that config-server serves centralized YAML files for the infrastructure services.

## Start config-server

```bash
docker compose up --build -d config-server
```

## Verify config-server health

```bash
curl http://localhost:8888/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Verify global application config

```bash
curl http://localhost:8888/application/default
```

Expected result:

The response contains:

```text
hms.name
hms.config-source
management.endpoints.web.exposure.include
```

## Verify eureka-server config

```bash
curl http://localhost:8888/eureka-server/default
```

Expected result:

The response contains:

```text
server.port
spring.application.name=eureka-server
eureka.client.register-with-eureka=false
eureka.client.fetch-registry=false
```

## Verify api-gateway config

```bash
curl http://localhost:8888/api-gateway/default
```

Expected result:

The response contains:

```text
server.port
spring.application.name=api-gateway
spring.cloud.gateway.routes
lb://auth-service
EUREKA_DEFAULT_ZONE
```

## Verify auth-service config

```bash
curl http://localhost:8888/auth-service/default
```

Expected result:

The response contains:

```text
server.port
spring.application.name=auth-service
spring.datasource.url
MYSQL_DATABASE
MYSQL_USER
MYSQL_PASSWORD
EUREKA_DEFAULT_ZONE
```

## Notes

auth-service is not implemented yet in the clean project restart.

For HMS-31, the goal is only to validate that config-server can serve the centralized auth-service configuration.

Full runtime validation of auth-service will be done in the future Auth epic.


## Test réel

Lance :

```bash
docker compose up --build -d config-server
```

Puis:

```bash
curl http://localhost:8888/application/default
curl http://localhost:8888/eureka-server/default
curl http://localhost:8888/api-gateway/default
curl http://localhost:8888/auth-service/default
```
