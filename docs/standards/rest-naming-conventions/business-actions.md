# Business Actions Convention

## Objective

This document defines how HMS APIs must expose business actions.

Business actions are operations that change the state of a resource.

Examples:

- confirm a reservation
- cancel a reservation
- check in a guest
- check out a guest
- pay an invoice
- assign a housekeeping task

## Main rule

Business actions must use:

```text
PATCH /api/resources/{id}/action
```

## Why PATCH?

Business actions usually modify only part of a resource state.

Example:

```text
Reservation status: CREATED → CONFIRMED
```

This is not a full replacement of the reservation, so `PATCH` is more appropriate than `PUT`.

## Reservation actions

```text
PATCH /api/reservations/{id}/confirm
PATCH /api/reservations/{id}/cancel
PATCH /api/reservations/{id}/check-in
PATCH /api/reservations/{id}/check-out
```

## Invoice actions

```text
PATCH /api/invoices/{id}/pay
PATCH /api/invoices/{id}/cancel
PATCH /api/invoices/{id}/refund
```

## Room actions

```text
PATCH /api/rooms/{id}/status
PATCH /api/rooms/{id}/mark-clean
PATCH /api/rooms/{id}/mark-maintenance
```

## Housekeeping actions

```text
PATCH /api/housekeeping-tasks/{id}/assign
PATCH /api/housekeeping-tasks/{id}/start
PATCH /api/housekeeping-tasks/{id}/complete
PATCH /api/housekeeping-tasks/{id}/cancel
```

## Staff actions

```text
PATCH /api/employees/{id}/activate
PATCH /api/employees/{id}/deactivate
```

## Naming rule

Business actions must use lowercase kebab-case.

Correct:

```text
check-in
check-out
mark-clean
mark-maintenance
```

Incorrect:

```text
checkIn
check_out
MarkClean
```

## Avoid action names in resource root

Correct:

```text
PATCH /api/reservations/{id}/confirm
```

Incorrect:

```text
POST /api/confirmReservation/{id}
POST /api/reservations/confirm/{id}
```

## Request body

A business action can have an optional request body when needed.

Example:

```text
PATCH /api/reservations/{id}/cancel
```

Body:

```json
{
  "reason": "Client request"
}
```

## Expected responses

Successful action:

```text
200 OK
```

Invalid transition:

```text
409 Conflict
```

Resource not found:

```text
404 Not Found
```

Invalid request body:

```text
400 Bad Request
```

## Final rule

Use `PATCH /api/resources/{id}/action` for business state transitions.
