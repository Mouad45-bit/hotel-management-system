# Exception Package

## Objective

The `exception` package contains custom exceptions and global exception handling.

It standardizes error responses across HMS microservices.

## Package path

```text
com.hotel.management.<servicename>.exception
```

Example:

```text
com.hotel.management.roomservice.exception
```

## Responsibilities

The exception package is responsible for:

- custom business exceptions
- technical exceptions specific to the service
- global exception handling with `@RestControllerAdvice`
- consistent HTTP error responses
- validation error formatting

## Forbidden responsibilities

Exception classes must not:

- contain business workflows
- access repositories
- call services
- expose sensitive internal details

## Custom exception example

```java
public class RoomNotFoundException extends RuntimeException {

    public RoomNotFoundException(Long id) {
        super("Room not found with id: " + id);
    }
}
```

## Global handler example

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RoomNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleRoomNotFound(RoomNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiErrorResponse(
                        "ROOM_NOT_FOUND",
                        ex.getMessage(),
                        HttpStatus.NOT_FOUND.value()
                ));
    }
}
```

## Standard error response

Recommended structure:

```java
public record ApiErrorResponse(
        String code,
        String message,
        int status
) {
}
```

## Naming convention

Custom exceptions must end with:

```text
Exception
```

Examples:

```text
RoomNotFoundException
ClientNotFoundException
ReservationConflictException
InvoiceAlreadyPaidException
```

Global handlers should be named:

```text
GlobalExceptionHandler
```
