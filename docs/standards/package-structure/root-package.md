# Root Package Standard

## Objective

Every HMS microservice must use a clear and predictable root package.

## Naming convention

```text
com.hotel.management.<servicename>
```

The `<servicename>` part must be written in lowercase and without hyphens.

## Examples

| Microservice | Root package |
|---|---|
| room-service | `com.hotel.management.roomservice` |
| client-service | `com.hotel.management.clientservice` |
| reservation-service | `com.hotel.management.reservationservice` |
| billing-service | `com.hotel.management.billingservice` |
| housekeeping-service | `com.hotel.management.housekeepingservice` |
| staff-service | `com.hotel.management.staffservice` |
| report-service | `com.hotel.management.reportservice` |

## Why not use hyphens?

Java package names cannot contain hyphens.

Correct:

```text
com.hotel.management.roomservice
```

Incorrect:

```text
com.hotel.management.room-service
```

## Main application class

The main Spring Boot class must be placed directly inside the root package.

Example for `room-service`:

```text
com.hotel.management.roomservice.RoomServiceApplication
```

## Spring Boot component scanning

Spring Boot automatically scans components located in the same package or sub-packages of the main application class.

That is why the application class must stay at the root package level.

Correct:

```text
com.hotel.management.roomservice
 ├── RoomServiceApplication.java
 ├── controller
 ├── service
 ├── repository
 └── entity
```

Incorrect:

```text
com.hotel.management.roomservice.app
 └── RoomServiceApplication.java

com.hotel.management.roomservice.controller
com.hotel.management.roomservice.service
```

In the incorrect example, Spring Boot may not automatically scan sibling packages such as `controller` or `service`.

