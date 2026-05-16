# HMS-22 - API Gateway Tests

## Build test

```bash
mvn -f api-gateway/pom.xml clean package
```

Expected result:

```text
BUILD SUCCESS
```

## Config Server test

```bash
curl http://localhost:8888/api-gateway/default
```

Expected result:

```text
The response contains api-gateway configuration.
```

## Gateway health test

```bash
curl http://localhost:8080/actuator/health
```

Expected result:

```text
{"status":"UP"}
```

## Auth route test

Command:

```bash
curl -i http://localhost:8080/api/auth/ping
```

Current expected result:

```text
404 Not Found or 503 Service Unavailable
```

Reason:

auth-service is not implemented yet in the clean project restart.
The objective of HMS-22 is to prepare the API Gateway route, not to validate the final auth-service endpoint.
Full validation will be done when auth-service is implemented and registered in Eureka.

## Eureka test

Open:

```bash
http://localhost:8761
```

Expected result:

API-GATEWAY appears in Eureka applications.

## Conclusion

The api-gateway starts successfully on port 8080.

It loads its configuration from config-server and registers itself in Eureka as API-GATEWAY.

The route `/api/auth/**` is configured to use `lb://auth-service`.
Full route validation requires auth-service to be running and registered in Eureka.
