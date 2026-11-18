# ApiError Model

## Objective

The `ApiError` model defines the standard response body for API errors.

It must be used for all non-validation errors.

Examples:

- resource not found
- business conflict
- unauthorized access
- forbidden access
- internal server error

## Standard JSON format

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 404,
  "error": "NOT_FOUND",
  "message": "Room not found with id: 12",
  "path": "/api/rooms/12"
}
```

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| timestamp | string | yes | Error creation date and time |
| status | integer | yes | HTTP status code |
| error | string | yes | Internal error code |
| message | string | yes | Human-readable message |
| path | string | yes | Request path |

## Java example

```java
public record ApiError(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        String path
) {
}
```

## Field explanations

### timestamp

Represents when the error happened.

Example:

```text
2026-05-16T14:30:00
```

### status

Represents the HTTP status code.

Examples:

```text
400
401
403
404
409
500
```

### error

Represents a stable technical error code.

Examples:

```text
BAD_REQUEST
UNAUTHORIZED
FORBIDDEN
NOT_FOUND
CONFLICT
INTERNAL_SERVER_ERROR
```

### message

Represents a readable explanation.

Example:

```text
Room not found with id: 12
```

### path

Represents the API path that caused the error.

Example:

```text
/api/rooms/12
```

## Rule

The `ApiError` model must not expose sensitive technical details such as stack traces, SQL queries or internal infrastructure information.
