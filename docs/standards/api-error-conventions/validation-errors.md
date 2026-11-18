# DTO Validation Error Convention

## Objective

This document defines how DTO validation errors must be returned by HMS APIs.

Validation errors happen when the request body does not respect DTO constraints.

Examples:

- `@NotBlank`
- `@NotNull`
- `@Email`
- `@Size`
- `@Positive`
- `@Future`
- `@Past`

## HTTP status

Validation errors must return:

```text
400 Bad Request
```

## Error code

Validation errors must use:

```text
VALIDATION_ERROR
```

## Example DTO

```java
public record RoomRequest(
        @NotBlank(message = "Room number is required")
        String number,

        @NotNull(message = "Room type is required")
        RoomType type,

        @NotNull(message = "Price per night is required")
        @Positive(message = "Price per night must be positive")
        BigDecimal pricePerNight
) {
}
```

## Invalid request example

```json
{
  "number": "",
  "type": null,
  "pricePerNight": -10
}
```

## Expected response

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "path": "/api/rooms",
  "fieldErrors": {
    "number": "Room number is required",
    "type": "Room type is required",
    "pricePerNight": "Price per night must be positive"
  }
}
```

## Field error rule

The `fieldErrors` object must contain:

```text
fieldName: validationMessage
```

Example:

```json
{
  "email": "Email format is invalid"
}
```

## Multiple validation errors

If several fields are invalid, all field errors should be returned in the same response.

Correct:

```json
{
  "fieldErrors": {
    "firstName": "First name is required",
    "email": "Email format is invalid",
    "phone": "Phone number is required"
  }
}
```

Incorrect:

```json
{
  "message": "Validation failed"
}
```

The incorrect example is not detailed enough for frontend forms.

## Final rule

DTO validation errors must always return a `ValidationError` response with `fieldErrors`.
