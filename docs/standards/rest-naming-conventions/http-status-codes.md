# HTTP Status Codes Convention

## Objective

This document defines the standard HTTP status codes used by HMS APIs.

## Success responses

### 200 OK

Use `200 OK` when a request succeeds and returns a response body.

Examples:

```text
GET /api/rooms
GET /api/rooms/{id}
PUT /api/rooms/{id}
PATCH /api/reservations/{id}/confirm
```

### 201 Created

Use `201 Created` when a new resource is created successfully.

Examples:

```text
POST /api/rooms
POST /api/clients
POST /api/reservations
```

### 204 No Content

Use `204 No Content` when a request succeeds but no response body is returned.

Examples:

```text
DELETE /api/rooms/{id}
DELETE /api/clients/{id}
```

## Client error responses

### 400 Bad Request

Use `400 Bad Request` when the request payload or parameters are invalid.

Examples:

- missing required field
- invalid email
- invalid date range
- invalid enum value

### 401 Unauthorized

Use `401 Unauthorized` when authentication is missing or invalid.

Examples:

- missing token
- invalid token
- expired token

### 403 Forbidden

Use `403 Forbidden` when the user is authenticated but does not have the required role.

Examples:

- receptionist tries to access admin-only endpoint
- housekeeping agent tries to access billing reports

### 404 Not Found

Use `404 Not Found` when the requested resource does not exist.

Examples:

```text
GET /api/rooms/999
GET /api/clients/999
GET /api/reservations/999
```

### 409 Conflict

Use `409 Conflict` when the request is valid but conflicts with a business rule.

Examples:

- room number already exists
- reservation overlaps with another reservation
- invoice is already paid
- reservation is already cancelled
- check-in is not allowed for the current reservation status

## Server error responses

### 500 Internal Server Error

Use `500 Internal Server Error` for unexpected technical errors.

Examples:

- unhandled exception
- database unavailable
- unexpected runtime failure

## Recommended mapping

| Situation | HTTP status |
|---|---|
| Read successful | 200 OK |
| Update successful | 200 OK |
| Business action successful | 200 OK |
| Create successful | 201 Created |
| Delete successful | 204 No Content |
| Validation error | 400 Bad Request |
| Missing or invalid token | 401 Unauthorized |
| Insufficient role | 403 Forbidden |
| Resource not found | 404 Not Found |
| Business conflict | 409 Conflict |
| Unexpected error | 500 Internal Server Error |

## Final rule

Every HMS API must return predictable HTTP status codes according to this convention.
