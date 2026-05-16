# Microservice Template Standard

## Objective

This document defines the standard structure that every future HMS microservice must follow.

The goal is to make all services consistent, readable, maintainable and easy to create.

This template will be used for future services such as:

- room-service
- client-service
- reservation-service
- billing-service
- housekeeping-service
- staff-service
- report-service

## Standard service structure

```text
service-name
 ├── Dockerfile
 ├── pom.xml
 ├── README.md
 └── src
     └── main
         ├── java
         │   └── com
         │       └── hotel
         │           └── management
         │               └── servicename
         │                   ├── ServiceNameApplication.java
         │                   ├── config
         │                   ├── controller
         │                   ├── dto
         │                   ├── entity
         │                   ├── exception
         │                   ├── mapper
         │                   ├── repository
         │                   └── service
         └── resources
             └── application.yml
```

## Root files

### Dockerfile

Each service must have its own Dockerfile.

The Dockerfile is responsible for:

- building the Spring Boot application
- creating a lightweight runtime image
- running the service with a non-root user
- exposing the correct service port

### pom.xml

Each service must have its own Maven configuration.

The pom.xml defines:

- Java version
- Spring Boot version
- Spring Cloud version
- required dependencies
- build plugins

### README.md

Each service must document:

- service responsibility
- exposed endpoints
- local run command
- Docker run command
- environment variables
- useful test commands

## Java package structure

Each service must use the following base package pattern:

```text
com.hotel.management.servicename
```

Example:

```text
com.hotel.management.roomservice
com.hotel.management.clientservice
com.hotel.management.reservationservice
```

## Mandatory packages

### config

Contains Spring configuration classes.

Examples:

- security configuration
- CORS configuration
- OpenAPI configuration
- client configuration

### controller

Contains REST controllers.

Controllers expose HTTP endpoints and must not contain business logic.

### service

Contains business logic.

The service layer coordinates repositories, validations and business rules.

### repository

Contains Spring Data repositories.

Repositories are responsible for database access only.

### entity

Contains JPA entities.

Entities represent database tables.

### dto

Contains request and response objects.

DTOs protect the API from exposing internal entity structure.

### mapper

Contains classes responsible for converting entities to DTOs and DTOs to entities.

### exception

Contains custom exceptions and global exception handlers.

## Mandatory technical behavior

Each service must:

- use Java 17
- use Spring Boot
- load configuration from config-server
- register itself in Eureka
- expose /actuator/health
- have its own Dockerfile
- own its own database if it stores data

## Database rule

A microservice must never access another microservice database directly.

Correct pattern:

```text
service A → REST/API call → service B
```

Forbidden pattern:

```text
service A → direct SQL query → service B database
```
