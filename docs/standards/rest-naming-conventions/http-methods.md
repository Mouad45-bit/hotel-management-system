# HTTP Methods Convention

## Objective

This document defines how HTTP methods must be used in HMS APIs.

## Summary

| Method | Usage |
|---|---|
| GET | Read data |
| POST | Create a new resource |
| PUT | Replace or fully update a resource |
| PATCH | Partially update a resource or trigger a business action |
| DELETE | Delete or deactivate a resource |

## GET

Use `GET` to read data.

Examples:

```text
GET /api/rooms
GET /api/rooms/{id}
GET /api/reservations?status=CONFIRMED
```

Rules:

- must not modify data
- can return one resource or a collection
- can use query parameters for filtering

## POST

Use `POST` to create a new resource.

Examples:

```text
POST /api/rooms
POST /api/clients
POST /api/reservations
```

Rules:

- request body contains the data to create
- response should return `201 Created`
- response body can contain the created resource

## PUT

Use `PUT` to replace or fully update a resource.

Examples:

```text
PUT /api/rooms/{id}
PUT /api/clients/{id}
PUT /api/reservations/{id}
```

Rules:

- request body should contain the full updated representation
- the target resource must already exist
- response usually returns `200 OK`

## PATCH

Use `PATCH` to partially update a resource or trigger a business action.

Partial update examples:

```text
PATCH /api/rooms/{id}/status
PATCH /api/employees/{id}/status
```

Business action examples:

```text
PATCH /api/reservations/{id}/confirm
PATCH /api/reservations/{id}/cancel
PATCH /api/reservations/{id}/check-in
PATCH /api/reservations/{id}/check-out
PATCH /api/invoices/{id}/pay
```

Rules:

- use for small targeted changes
- use for explicit business transitions
- response usually returns `200 OK`

## DELETE

Use `DELETE` to delete or deactivate a resource.

Examples:

```text
DELETE /api/rooms/{id}
DELETE /api/clients/{id}
DELETE /api/reservations/{id}
```

Rules:

- physical deletion is not always recommended
- soft delete is preferred for important business data
- response can return `204 No Content`

## Final rule

Do not put action verbs in CRUD resource names.

Correct:

```text
POST /api/rooms
```

Incorrect:

```text
POST /api/createRoom
```
