# HMS-5 - Eureka Server Tests

## Config Server health

Command:

```bash
curl http://localhost:8888/actuator/health
```

Expected result:

```json
{"status":"UP"}
```

## Eureka configuration served by config-server

Command:

```bash
curl http://localhost:8888/eureka-server/default
```

Expected result:

The response contains:

```text
server.port=8761
eureka.client.register-with-eureka=false
eureka.client.fetch-registry=false
```

## Eureka Server health

Command:

```bash
curl http://localhost:8761/actuator/health
```

Expected result:

```json
{"status":"UP"}
```

## Eureka dashboard

URL:

```text
http://localhost:8761
```

Expected result:

The Eureka dashboard is accessible.
