# 409 Conflict Error Convention

## Objective

This document defines when HMS APIs must return `409 Conflict`.

A conflict error happens when the request is technically valid, but it conflicts with the current business state.

## HTTP status

Business conflicts must return:

```text
409 Conflict
```

## Error code

Conflict errors must use:

```text
CONFLICT
```

## When to use 409 Conflict

Use `409 Conflict` when:

- the request body is valid
- the authenticated user is allowed to perform the action
- the resource may exist
- but the operation cannot be completed because of a business conflict

## Examples

### Duplicate room number

Request:

```text
POST /api/rooms
```

Business rule:

```text
A room number must be unique.
```

Expected response:

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 409,
  "error": "CONFLICT",
  "message": "Room number already exists: 101",
  "path": "/api/rooms"
}
```

### Reservation overlap

Request:

```text
POST /api/reservations
```

Business rule:

```text
A room cannot have two active reservations for overlapping dates.
```

Expected response:

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 409,
  "error": "CONFLICT",
  "message": "Room is already reserved for the selected period",
  "path": "/api/reservations"
}
```

### Invoice already exists

Request:

```text
POST /api/invoices/reservation/15
```

Business rule:

```text
A reservation cannot have two active invoices.
```

Expected response:

```json
{
  "timestamp": "2026-05-16T14:30:00",
  "status": 409,
  "error": "CONFLICT",
  "message": "An invoice already exists for reservation id: 15",
  "path": "/api/invoices/reservation/15"
}
```

## 400 vs 409

Use `400 Bad Request` when the request is invalid.

Example:

```text
Missing required field.
```

Use `409 Conflict` when the request is valid but violates the current business state.

Example:

```text
The room is already reserved.
```

## Final rule

Use `409 Conflict` for valid requests that cannot be completed because of business state conflicts.
