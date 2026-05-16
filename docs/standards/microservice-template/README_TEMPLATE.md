# service-name

Short description of the service responsibility.

Example:

```text
room-service manages hotel rooms, room types, prices and room statuses.
```

## Responsibility

This service is responsible for:

- main responsibility 1
- main responsibility 2
- main responsibility 3

This service is not responsible for:

- responsibility owned by another service
- direct access to another service database

## Technical stack

- Java 17
- Spring Boot
- Spring Cloud Config Client
- Eureka Client
- Spring Boot Actuator
- Maven
- Docker

## Package structure

```text
src/main/java/com/hotel/management/servicename
 ├── ServiceNameApplication.java
 ├── config
 ├── controller
 ├── dto
 ├── entity
 ├── exception
 ├── mapper
 ├── repository
 └── service
```

## Local run

Start config-server and eureka-server first.

```bash
mvn clean package
java -jar target/service-name-0.0.1-SNAPSHOT.jar
```

## Docker build

```bash
docker build -t hms/service-name:local .
```

## Docker run

```bash
docker run --rm -p 808X:808X hms/service-name:local
```

## Healthcheck

```bash
curl http://localhost:808X/actuator/health
```

Expected response:

```json
{
  "status": "UP"
}
```

## Configuration

Local bootstrap configuration:

```yaml
spring:
  application:
    name: service-name
  config:
    import: ${SPRING_CONFIG_IMPORT:optional:configserver:http://localhost:8888}
```

Centralized configuration must be placed in:

```text
config-server/src/main/resources/configs/service-name.yml
```

## Environment variables

| Variable | Description | Example |
|---|---|---|
| SERVICE_NAME_PORT | Service HTTP port | 808X |
| SPRING_CONFIG_IMPORT | Config server URL | configserver:http://config-server:8888 |
| EUREKA_DEFAULT_ZONE | Eureka URL | http://eureka-server:8761/eureka/ |

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /actuator/health | Service health |
| GET | /actuator/info | Service info |

## Notes

This service must communicate with other services through REST APIs.

It must not access another service database directly.
