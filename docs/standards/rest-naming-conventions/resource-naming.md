# Resource Naming Convention

## Objective

This document defines how REST resources must be named in HMS APIs.

## Main rule

REST resources must use plural nouns.

## Correct examples

```text
/api/rooms
/api/clients
/api/reservations
/api/invoices
/api/housekeeping-tasks
/api/employees
/api/reports
```

## Incorrect examples

```text
/api/room
/api/client
/api/getRooms
/api/createClient
/api/reservationList
```

## Why plural names?

Plural names represent collections.

Example:

```text
GET /api/rooms
```

means: retrieve the collection of rooms.

```text
GET /api/rooms/{id}
```

means: retrieve one item from the rooms collection.

## Resource names must be nouns

A resource name represents a domain object or collection.

Correct:

```text
/api/rooms
/api/clients
/api/reservations
```

Incorrect:

```text
/api/getRooms
/api/createReservation
/api/payInvoice
```

Actions must be represented by HTTP methods or action suffixes, not by resource names.

## Multi-word resources

Multi-word resource names must use kebab-case.

Correct:

```text
/api/housekeeping-tasks
/api/room-types
/api/payment-methods
```

Incorrect:

```text
/api/housekeepingTasks
/api/room_types
/api/RoomTypes
```

## Recommended HMS resource names

| Domain | Resource path |
|---|---|
| Auth users | `/api/users` |
| Rooms | `/api/rooms` |
| Room types | `/api/room-types` |
| Clients | `/api/clients` |
| Reservations | `/api/reservations` |
| Invoices | `/api/invoices` |
| Payments | `/api/payments` |
| Housekeeping tasks | `/api/housekeeping-tasks` |
| Employees | `/api/employees` |
| Reports | `/api/reports` |

## Service naming vs resource naming

Microservice names use service-oriented names:

```text
room-service
client-service
reservation-service
billing-service
```

REST resource names represent business resources:

```text
/api/rooms
/api/clients
/api/reservations
/api/invoices
```

## Final rule

Use plural, lowercase, kebab-case nouns for REST resources.
