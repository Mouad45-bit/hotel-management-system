# Template Validation with room-service

## Objective

This document validates that the microservice template can be applied to a future `room-service`.

The goal is not to implement `room-service` now.

The goal is only to verify that the template is realistic and complete enough.

## Future service name

```text
room-service
```

## Future responsibility

`room-service` will manage hotel rooms.

It will be responsible for:

- room creation
- room update
- room status management
- room type management
- room availability information
- room price per night

It will not be responsible for:

- reservations
- invoices
- user authentication
- housekeeping tasks

## Expected package

```text
com.hotel.management.roomservice
```

## Expected structure

```text
room-service
 ├── Dockerfile
 ├── pom.xml
 ├── README.md
 └── src
     └── main
         ├── java
         │   └── com
         │       └── hotel
         │           └── management
         │               └── roomservice
         │                   ├── RoomServiceApplication.java
         │                   ├── config
         │                   ├── controller
         │                   │   └── RoomController.java
         │                   ├── dto
         │                   │   ├── RoomRequest.java
         │                   │   └── RoomResponse.java
         │                   ├── entity
         │                   │   ├── Room.java
         │                   │   ├── RoomStatus.java
         │                   │   └── RoomType.java
         │                   ├── exception
         │                   │   ├── RoomNotFoundException.java
         │                   │   └── GlobalExceptionHandler.java
         │                   ├── mapper
         │                   │   └── RoomMapper.java
         │                   ├── repository
         │                   │   └── RoomRepository.java
         │                   └── service
         │                       └── RoomService.java
         └── resources
             └── application.yml
```

## Expected local application.yml

```yaml
spring:
  application:
    name: room-service
  config:
    import: ${SPRING_CONFIG_IMPORT:optional:configserver:http://localhost:8888}
```

## Expected centralized configuration

File:

```text
config-server/src/main/resources/configs/room-service.yml
```

Content example:

```yaml
server:
  port: ${ROOM_SERVICE_PORT:8082}

spring:
  application:
    name: room-service

  datasource:
    url: jdbc:mariadb://${ROOM_DB_HOST:localhost}:${ROOM_DB_PORT:3308}/${ROOM_DB_NAME:db_room}
    username: ${ROOM_DB_USER:hotel_user}
    password: ${ROOM_DB_PASSWORD:hotel_pass}
    driver-class-name: org.mariadb.jdbc.Driver

  jpa:
    hibernate:
      ddl-auto: update
    open-in-view: false
    show-sql: false

eureka:
  instance:
    prefer-ip-address: true
  client:
    service-url:
      defaultZone: ${EUREKA_DEFAULT_ZONE:http://localhost:8761/eureka/}

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

## Expected dependencies

The template dependencies are enough for `room-service`.

Required:

- spring-boot-starter-web
- spring-cloud-starter-config
- spring-cloud-starter-netflix-eureka-client
- spring-boot-starter-actuator
- spring-boot-starter-validation
- spring-boot-starter-data-jpa
- mariadb-java-client
- lombok
- spring-boot-starter-test

## Expected technical endpoints

```text
GET /actuator/health
GET /actuator/info
```

## Expected future business endpoints

```text
POST   /api/rooms
GET    /api/rooms
GET    /api/rooms/{id}
PUT    /api/rooms/{id}
DELETE /api/rooms/{id}
PATCH  /api/rooms/{id}/status
GET    /api/rooms/available
```

## Validation conclusion

The microservice template is valid for `room-service`.

It provides:

- a clear package structure
- a minimal local configuration
- a centralized configuration model
- a standard Dockerfile
- required technical endpoints
- README documentation
- database-per-service compatibility
- Eureka registration compatibility
- config-server compatibility

The template can be reused later for:

- client-service
- reservation-service
- billing-service
- housekeeping-service
- staff-service
- report-service
