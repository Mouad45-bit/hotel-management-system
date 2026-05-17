# API Error Response Examples

## Objective

This document provides concrete JSON examples for standard HMS API errors.

## 400 Bad Request

Use this response when the request payload or parameters are invalid.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 400,
  "error": "BAD_REQUEST",
  "message": "Invalid request",
  "path": "/api/rooms"
}
```

## 400 Validation Error

Use this response when DTO validation fails.

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

## 401 Unauthorized

Use this response when authentication is missing or invalid.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 401,
  "error": "UNAUTHORIZED",
  "message": "Authentication is required",
  "path": "/api/reservations"
}
```

## 403 Forbidden

Use this response when the user is authenticated but does not have the required role.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 403,
  "error": "FORBIDDEN",
  "message": "Access denied",
  "path": "/api/reports/revenue"
}
```

## 404 Not Found

Use this response when the requested resource does not exist.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 404,
  "error": "NOT_FOUND",
  "message": "Room not found with id: 12",
  "path": "/api/rooms/12"
}
```

## 409 Conflict

Use this response when the request is valid but conflicts with a business rule.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 409,
  "error": "CONFLICT",
  "message": "Room is already reserved for the selected period",
  "path": "/api/reservations"
}
```

## 500 Internal Server Error

Use this response for unexpected technical errors.

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 500,
  "error": "INTERNAL_SERVER_ERROR",
  "message": "An unexpected error occurred",
  "path": "/api/rooms"
}
```

## Final rule

All error examples must follow the standard `ApiError` or `ValidationError` format.
