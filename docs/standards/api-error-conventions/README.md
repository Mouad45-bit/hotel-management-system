# API Error Conventions

## Objective

This documentation defines the standard error response format for all HMS microservices.

The goal is to make API errors consistent, readable and easy to handle by frontend clients.

These conventions apply to future services such as:

- auth-service
- room-service
- client-service
- reservation-service
- billing-service
- housekeeping-service
- staff-service
- report-service

## Why standardize API errors?

Without a common format, each service may return errors differently.

That would make frontend error handling harder.

A common error format helps:

- frontend developers display errors consistently
- backend developers implement predictable handlers
- API consumers understand failures quickly
- logs and debugging become easier
- future services reuse the same pattern

## Standard error response

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 404,
  "error": "NOT_FOUND",
  "message": "Room not found with id: 12",
  "path": "/api/rooms/12"
}
```

## Validation error response

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

## Mandatory fields

| Field | Description |
|---|---|
| timestamp | Date and time when the error occurred |
| status | HTTP status code |
| error | Internal error code |
| message | Human-readable error message |
| path | Request path that caused the error |

## Additional field for validation errors

| Field | Description |
|---|---|
| fieldErrors | Map of field names and validation messages |

## Final rule

Every HMS microservice must return errors using this convention.
