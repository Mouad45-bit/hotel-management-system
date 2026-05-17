# ValidationError Model

## Objective

The `ValidationError` model defines the standard response body for DTO validation errors.

It must be used when request validation fails.

Examples:

- `@NotBlank`
- `@NotNull`
- `@Email`
- `@Size`
- `@Positive`
- `@Future`
- `@Past`

## Standard JSON format

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "path": "/api/rooms",
  "fieldErrors": {
    "number": "Room number is required",
    "pricePerNight": "Price per night must be positive"
  }
}
```

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| timestamp | string | yes | Error creation date and time |
| status | integer | yes | HTTP status code |
| error | string | yes | Internal error code |
| message | string | yes | General validation message |
| path | string | yes | Request path |
| fieldErrors | object | yes | Map of field names and validation messages |

## Java example

```java
public record ValidationError(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, String> fieldErrors
) {
}
```

## Why fieldErrors?

A single request body can contain multiple invalid fields.

Example request:

```json
{
  "number": "",
  "pricePerNight": -10
}
```

Expected response:

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "path": "/api/rooms",
  "fieldErrors": {
    "number": "Room number is required",
    "pricePerNight": "Price per night must be positive"
  }
}
```

## Rule

Validation errors must always return `400 Bad Request`.
