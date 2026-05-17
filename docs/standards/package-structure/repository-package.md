# Repository Package

## Objective

The `repository` package contains database access components.

In HMS microservices, repositories are usually Spring Data JPA interfaces.

## Package path

```text
com.hotel.management.<servicename>.repository
```

Example:

```text
com.hotel.management.roomservice.repository
```

## Responsibilities

Repositories are responsible for:

- reading data from the service database
- writing data to the service database
- defining query methods
- exposing persistence operations to the service layer

## Forbidden responsibilities

Repositories must not contain:

- business logic
- HTTP logic
- DTO mapping
- calls to other microservices
- direct access to another microservice database

## Correct pattern

```text
Service
    ↓
Repository
    ↓
Own database
```

## Database per service rule

A repository must access only the database owned by its microservice.

Correct:

```text
room-service → RoomRepository → db_room
```

Forbidden:

```text
reservation-service → direct SQL query → db_room
```

If one service needs data from another service, it must use an API call, not direct database access.

## Example

```java
@Repository
public interface RoomRepository extends JpaRepository<Room, Long> {

    boolean existsByNumber(String number);

    List<Room> findByStatus(RoomStatus status);
}
```

## Explanation

Spring Data JPA automatically provides the implementation at runtime.

The developer only defines the interface and method names.

## Naming convention

Repository interfaces must end with:

```text
Repository
```

Examples:

```text
RoomRepository
ClientRepository
ReservationRepository
BillingRepository
```
