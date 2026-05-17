# CRUD Endpoints Convention

## Objective

This document defines the standard CRUD endpoint pattern for HMS microservices.

CRUD means:

- Create
- Read
- Update
- Delete

## Standard pattern

For a resource named `resources`, the standard endpoints are:

```text
GET    /api/resources
GET    /api/resources/{id}
POST   /api/resources
PUT    /api/resources/{id}
PATCH  /api/resources/{id}/action
DELETE /api/resources/{id}
```

## List resources

```text
GET /api/resources
```

Purpose:

```text
Return a list of resources.
```

Example:

```text
GET /api/rooms
GET /api/clients
GET /api/reservations
```

Expected response:

```text
200 OK
```

## Get resource by id

```text
GET /api/resources/{id}
```

Purpose:

```text
Return one resource by its identifier.
```

Example:

```text
GET /api/rooms/1
GET /api/clients/1
GET /api/reservations/1
```

Expected responses:

```text
200 OK
404 Not Found
```

## Create resource

```text
POST /api/resources
```

Purpose:

```text
Create a new resource.
```

Example:

```text
POST /api/rooms
POST /api/clients
POST /api/reservations
```

Expected responses:

```text
201 Created
400 Bad Request
409 Conflict
```

## Update resource

```text
PUT /api/resources/{id}
```

Purpose:

```text
Update a complete resource.
```

Example:

```text
PUT /api/rooms/1
PUT /api/clients/1
PUT /api/reservations/1
```

Expected responses:

```text
200 OK
400 Bad Request
404 Not Found
409 Conflict
```

## Partial update or action

```text
PATCH /api/resources/{id}/action
```

Purpose:

```text
Modify part of a resource or execute a business transition.
```

Example:

```text
PATCH /api/rooms/1/status
PATCH /api/reservations/1/confirm
PATCH /api/invoices/1/pay
```

Expected responses:

```text
200 OK
400 Bad Request
404 Not Found
409 Conflict
```

## Delete resource

```text
DELETE /api/resources/{id}
```

Purpose:

```text
Delete or deactivate a resource.
```

Example:

```text
DELETE /api/rooms/1
DELETE /api/clients/1
DELETE /api/reservations/1
```

Expected responses:

```text
204 No Content
404 Not Found
409 Conflict
```

## Example: rooms API

```text
GET    /api/rooms
GET    /api/rooms/{id}
POST   /api/rooms
PUT    /api/rooms/{id}
PATCH  /api/rooms/{id}/status
DELETE /api/rooms/{id}
```

## Example: clients API

```text
GET    /api/clients
GET    /api/clients/{id}
POST   /api/clients
PUT    /api/clients/{id}
DELETE /api/clients/{id}
```

## Example: reservations API

```text
GET    /api/reservations
GET    /api/reservations/{id}
POST   /api/reservations
PUT    /api/reservations/{id}
PATCH  /api/reservations/{id}/confirm
PATCH  /api/reservations/{id}/cancel
PATCH  /api/reservations/{id}/check-in
PATCH  /api/reservations/{id}/check-out
DELETE /api/reservations/{id}
```

## Final rule

Every HMS microservice must reuse this CRUD structure unless a specific business reason justifies an exception.
