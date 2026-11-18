# Service Package

## Objective

The `service` package contains the business logic of a microservice.

It is the central layer between controllers and repositories.

## Package path

```text
com.hotel.management.<servicename>.service
```

Example:

```text
com.hotel.management.roomservice.service
```

## Responsibilities

Services are responsible for:

- applying business rules
- coordinating repositories
- validating business constraints
- performing calculations
- managing transactions
- calling other services if needed
- converting data through mappers when appropriate

## Forbidden responsibilities

Services must not:

- expose HTTP endpoints directly
- depend on HTTP request or response objects
- return raw database entities to controllers if DTOs are required
- contain framework-specific routing logic

## Correct pattern

```text
Controller
    ↓
Service
    ↓
Repository
```

## Example

```java
@Service
@RequiredArgsConstructor
public class RoomService {

    private final RoomRepository roomRepository;
    private final RoomMapper roomMapper;

    public RoomResponse createRoom(RoomRequest request) {
        if (roomRepository.existsByNumber(request.number())) {
            throw new RoomAlreadyExistsException(request.number());
        }

        Room room = roomMapper.toEntity(request);
        Room savedRoom = roomRepository.save(room);

        return roomMapper.toResponse(savedRoom);
    }
}
```

## Explanation

The service is the correct place for business rules.

In this example, the rule "a room number must be unique" belongs to the service layer.

## Naming convention

Service classes must end with:

```text
Service
```

Examples:

```text
RoomService
ClientService
ReservationService
BillingService
```

## Transaction rule

Write operations should use `@Transactional` when several database operations must succeed or fail together.

Example:

```java
@Transactional
public ReservationResponse createReservation(ReservationRequest request) {
    // business operation
}
```
