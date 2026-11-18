# HMS-4 - Config Server Tests

## Local test

Command:

```bash
mvn -f config-server/pom.xml clean package
java -jar config-server/target/config-server-0.0.1-SNAPSHOT.jar
curl http://localhost:8888/actuator/health
```

Expected result:

{"status":"UP"}

## Config endpoint test

Command:

```bash
curl http://localhost:8888/application/default
```

Expected result:

The response contains configuration loaded from:

config-server/src/main/resources/configs/application.yml

## Docker test

Command:

```bash
docker build -t hms/config-server:local ./config-server
docker run --rm -p 8888:8888 hms/config-server:local
curl http://localhost:8888/actuator/health
```

