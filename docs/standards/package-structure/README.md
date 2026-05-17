# Standard Package Structure

## Objective

This documentation defines the standard Java package structure for all HMS microservices.

The goal is to make every service consistent, readable and easy to maintain.

This standard applies to future services such as:

- room-service
- client-service
- reservation-service
- billing-service
- housekeeping-service
- staff-service
- report-service

## Target structure

```text
service-name
 └── src/main/java/com/hotel/management/servicename
      ├── Application.java
      ├── controller
      ├── service
      ├── repository
      ├── entity
      ├── dto
      ├── mapper
      ├── exception
      └── config
```

## Mandatory packages

| Package | Responsibility |
|---|---|
| controller | Exposes REST endpoints |
| service | Contains business logic |
| repository | Accesses the database |
| entity | Represents database tables |
| dto | Defines API request and response objects |
| mapper | Converts entities and DTOs |
| exception | Contains custom exceptions and handlers |
| config | Contains technical configuration classes |

## Rule

All future HMS microservices must follow this structure unless a strong architectural reason justifies an exception.
