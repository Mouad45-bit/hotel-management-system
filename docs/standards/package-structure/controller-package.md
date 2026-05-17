# Controller Package

## Objective

The `controller` package contains REST controllers.

Controllers are responsible for exposing HTTP endpoints to external clients through the API Gateway.

## Package path

```text
com.hotel.management.<servicename>.controller
```

Example:

```text
com.hotel.management.roomservice.controller
```

## Responsibilities

Controllers are responsible for:

- receiving HTTP requests
- validating request bodies with annotations such as `@Valid`
- calling the service layer
- returning HTTP responses
- choosing appropriate HTTP status codes

## Forbidden responsibilities

Controllers must not contain:

- complex business logic
- database access
- price calculations
- availability algorithms
- direct calls to repositories
- transaction logic

## Correct pattern

```text
HTTP request
    ↓
Controller
    ↓
Service
    ↓
Repository
```

## Example

```java
@RestController
@RequestMapping("/api/rooms")
@RequiredArgsConstructor
public class RoomController {

    private final RoomService roomService;

    @PostMapping
    public ResponseEntity<RoomResponse> createRoom(@Valid @RequestBody RoomRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(roomService.createRoom(request));
    }
}
```

## Explanation

The controller receives the request and delegates the business operation to the service.

The method does not contain business rules.

## Naming convention

Controller classes must end with:

```text
Controller
```

Examples:

```text
RoomController
ClientController
ReservationController
BillingController
```
