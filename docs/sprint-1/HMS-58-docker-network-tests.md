# HMS-58 - Docker Network Tests

## Objective

Create a shared Docker network named `hotel-network` so microservices can communicate using Docker service names.

## Services connected in this story

- config-server
- eureka-server

## Deferred services

The following services are not yet available in the clean project restart:

- auth-service
- api-gateway
- db-auth

Their network connection will be completed when the corresponding services are created.

## Start environment

```bash
docker compose up --build -d
```

## Verify containers

```bash
docker compose ps
```

Expected result:

```text
config-server    running / healthy
eureka-server    running / healthy
```

## Verify Docker network

```bash
docker network inspect hotel-network
```

Expected result:

The network contains:

```text
config-server
eureka-server
```

## Test DNS from eureka-server to config-server

```bash
docker compose exec eureka-server curl -f http://config-server:8888/actuator/health
```

Expected result:

```json
{"status":"UP"}
```

## Test DNS from config-server to eureka-server

```bash
docker compose exec config-server curl -f http://eureka-server:8761/actuator/health
```

Expected result:

```json
{"status":"UP"}
```

## Conclusion

The Docker network `hotel-network` is working.
Services can communicate using container names without fixed IP addresses.
