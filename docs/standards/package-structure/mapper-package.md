# Mapper Package

## Objective

The `mapper` package contains conversion logic between entities and DTOs.

Mappers keep controllers and services cleaner.

## Package path

```text
com.hotel.management.<servicename>.mapper
```

Example:

```text
com.hotel.management.roomservice.mapper
```

## Responsibilities

Mappers are responsible for:

- converting request DTOs to entities
- converting entities to response DTOs
- centralizing repetitive transformation logic
- preventing mapping logic from spreading across controllers and services

## Forbidden responsibilities

Mappers must not:

- access repositories
- call external services
- contain business decisions
- perform database operations
- validate complex business rules

## Correct pattern

```text
Request DTO
    ↓
Mapper
    ↓
Entity
```

```text
Entity
    ↓
Mapper
    ↓
Response DTO
```

## Example

```java
@Component
public class RoomMapper {

    public Room toEntity(RoomRequest request) {
        return Room.builder()
                .number(request.number())
                .type(request.type())
                .pricePerNight(request.pricePerNight())
                .status(RoomStatus.AVAILABLE)
                .build();
    }

    public RoomResponse toResponse(Room room) {
        return new RoomResponse(
                room.getId(),
                room.getNumber(),
                room.getType(),
                room.getStatus(),
                room.getPricePerNight()
        );
    }
}
```

## Explanation

The mapper can set simple default values if they are part of object construction.

Complex decisions must stay in the service layer.

## Naming convention

Mapper classes must end with:

```text
Mapper
```

Examples:

```text
RoomMapper
ClientMapper
ReservationMapper
BillingMapper
```
