room-service
==========

Room management microservice for the Hotel Management System.

Responsibility
---------

This service is responsible for:

- room inventory
- room status
- room type
- room price per night
- room capacity

This service is not responsible for:

- reservations
- invoices
- authentication
- housekeeping tasks

Technical stack
---------

- Java 17
- Spring Boot
- Spring Cloud Config Client
- Eureka Client
- Spring Boot Actuator
- Spring Data JPA
- MariaDB
- Maven
- Docker

Package structure
---------

```text
src/main/java/com/hotel/management/roomservice
 ├── RoomServiceApplication.java
 ├── config
 ├── controller
 ├── dto
 ├── entity
 ├── exception
 ├── mapper
 ├── repository
 └── service
```

Local run
---------

Start config-server, eureka-server and db-room first.

```
mvn -f room-service/pom.xml clean package
java -jar room-service/target/room-service-0.0.1-SNAPSHOT.jar
```

Healthcheck
-----------

```
curl http://localhost:8082/actuator/health
```

Expected response:

```
{
  "status": "UP"
}
```

Ping endpoint
-------------

```
curl http://localhost:8082/api/rooms/ping
```

Expected response:

```
{  
  "service": "room-service",  
  "status": "UP"
}
```

Notes
-----

Business endpoints will be implemented in the next sprint.
