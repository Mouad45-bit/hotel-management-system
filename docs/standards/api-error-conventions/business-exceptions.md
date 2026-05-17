# Standard Business Exceptions

## Objective

This document defines the standard exception types that future HMS microservices can reuse.

These exceptions help every service map business failures to consistent HTTP responses.

## Standard exceptions

| Exception | HTTP status | Usage |
|---|---:|---|
| ResourceNotFoundException | 404 | Requested resource does not exist |
| BusinessException | 400 | Generic business rule failure |
| ConflictException | 409 | Valid request conflicts with business state |
| UnauthorizedException | 401 | Missing or invalid authentication |
| ForbiddenException | 403 | Authenticated user lacks permission |

## ResourceNotFoundException

Use this exception when a resource does not exist.

Example:

```java
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String resourceName, Object id) {
        super(resourceName + " not found with id: " + id);
    }
}
```

Example usage:

```java
throw new ResourceNotFoundException("Room", roomId);
```

Expected HTTP response:

```text
404 Not Found
```

## BusinessException

Use this exception for business rule violations that do not fit a more specific exception.

Example:

```java
public class BusinessException extends RuntimeException {

    public BusinessException(String message) {
        super(message);
    }
}
```

Expected HTTP response:

```text
400 Bad Request
```

## ConflictException

Use this exception when the request is valid but conflicts with the current business state.

Examples:

- room number already exists
- reservation overlaps another reservation
- invoice already exists for a reservation
- invoice is already paid

Example:

```java
public class ConflictException extends RuntimeException {

    public ConflictException(String message) {
        super(message);
    }
}
```

Expected HTTP response:

```text
409 Conflict
```

## UnauthorizedException

Use this exception when authentication is missing or invalid.

Examples:

- missing token
- invalid token
- expired token

Expected HTTP response:

```text
401 Unauthorized
```

## ForbiddenException

Use this exception when the user is authenticated but does not have the required role.

Examples:

- receptionist tries to access admin-only endpoint
- housekeeping agent tries to access billing reports

Expected HTTP response:

```text
403 Forbidden
```

## Naming rule

Custom exceptions must end with:

```text
Exception
```

Correct:

```text
RoomNotFoundException
ReservationConflictException
InvoiceAlreadyPaidException
```

Incorrect:

```text
RoomError
ReservationProblem
BadInvoice
```

## Final rule

Each service can create domain-specific exceptions, but they must map to the standard HTTP statuses defined in this convention.
