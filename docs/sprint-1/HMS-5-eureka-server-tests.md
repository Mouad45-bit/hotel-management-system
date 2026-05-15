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

## Client registration test

Command:

```bash
curl -X POST http://localhost:8761/eureka/apps/TEST-CLIENT \
  -H "Content-Type: application/json" \
  -d '{
    "instance": {
      "instanceId": "test-client-1",
      "hostName": "localhost",
      "app": "TEST-CLIENT",
      "ipAddr": "127.0.0.1",
      "status": "UP",
      "port": {
        "$": 9999,
        "@enabled": "true"
      },
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

Verification:

```bash
curl http://localhost:8761/eureka/apps/TEST-CLIENT
```

Expected result:

The registered application `TEST-CLIENT` appears in the Eureka registry.

Note:

This test simulates a Eureka client registration. A real Spring Boot client registration will be tested again when auth-service or api-gateway is added.
