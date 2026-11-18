# REST Naming Conventions

## Objective

This documentation defines the REST API naming conventions for all HMS microservices.

The goal is to make every API consistent, predictable and easy to consume.

These conventions apply to future services such as:

- auth-service
- room-service
- client-service
- reservation-service
- billing-service
- housekeeping-service
- staff-service
- report-service

## Global rules

Every business API route must:

- start with `/api`
- use plural resource names
- use nouns for resources
- use HTTP methods correctly
- use query parameters for filters
- use path variables for resource identifiers
- use standard HTTP status codes

## Standard CRUD pattern

```text
GET    /api/resources
GET    /api/resources/{id}
POST   /api/resources
PUT    /api/resources/{id}
PATCH  /api/resources/{id}/action
DELETE /api/resources/{id}
GET    /api/resources/search?param=value
```

## Example with rooms

```text
GET    /api/rooms
GET    /api/rooms/{id}
POST   /api/rooms
PUT    /api/rooms/{id}
PATCH  /api/rooms/{id}/status
DELETE /api/rooms/{id}
GET    /api/rooms/search?status=AVAILABLE&type=DOUBLE
```

## Why this standard matters

Consistent REST naming helps:

- backend developers implement APIs faster
- frontend developers consume APIs more easily
- reviewers detect inconsistent routes
- API Gateway route definitions stay predictable
- documentation remains easier to maintain
