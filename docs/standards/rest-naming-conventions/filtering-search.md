# Filtering and Search Convention

## Objective

This document defines how filtering and search must be handled in HMS REST APIs.

## Main rule

Filters must use query parameters.

## Basic filtering

Use query parameters on collection endpoints.

Pattern:

```text
GET /api/resources?param=value
```

Examples:

```text
GET /api/rooms?status=AVAILABLE
GET /api/reservations?clientId=1&status=CONFIRMED
GET /api/invoices?status=PAID
```

## Multiple filters

Use multiple query parameters.

Example:

```text
GET /api/rooms?status=AVAILABLE&type=DOUBLE&floor=2
```

## Date filtering

Use ISO date format.

Example:

```text
GET /api/reservations?startDate=2026-05-01&endDate=2026-05-10
```

Recommended date format:

```text
YYYY-MM-DD
```

## Search endpoint

Use `/search` when the operation is a keyword-based or multi-field search, not a simple exact filter.

Filtering means that the client knows the exact field to filter on.

Example:

```text
GET /api/rooms?status=AVAILABLE
```

Search means that the backend may look for a value across multiple fields.

Example:

```text
GET /api/clients/search?keyword=ali
```

Pattern:

```text
GET /api/resources/search?keyword=value
```

Examples:

```text
GET /api/clients/search?keyword=ali
GET /api/reservations/search?keyword=ali
GET /api/rooms/search?keyword=suite
```

In these examples, the backend may search the keyword in several fields.

For clients, `keyword=ali` may search in:

```text
firstName
lastName
email
phone
cin
passportNumber
```

For rooms, `keyword=suite` may search in:

```text
number
type
description
```

## When not to use /search

Do not use `/search` for simple exact filters.

Correct:

```text
GET /api/rooms?status=AVAILABLE&type=DOUBLE
```

Incorrect:

```text
GET /api/rooms/search?status=AVAILABLE&type=DOUBLE
```

Correct:

```text
GET /api/reservations?clientId=1&status=CONFIRMED
```

Incorrect:

```text
GET /api/reservations/search?clientId=1&status=CONFIRMED
```

## Pagination

For large collections, use:

```text
page
size
sort
```

Example:

```text
GET /api/rooms?page=0&size=20&sort=number,asc
```

## Sorting

Sorting must use the `sort` query parameter.

Pattern:

```text
sort=field,direction
```

Examples:

```text
GET /api/rooms?sort=number,asc
GET /api/reservations?sort=startDate,desc
GET /api/invoices?sort=createdAt,desc
```

## Query parameter naming

Query parameters must use camelCase.

Correct:

```text
clientId
startDate
endDate
roomType
```

Incorrect:

```text
client_id
start_date
end-date
RoomType
```

## Avoid filter values in the path

Correct:

```text
GET /api/rooms?status=AVAILABLE
```

Incorrect:

```text
GET /api/rooms/status/AVAILABLE
```

Correct:

```text
GET /api/reservations?clientId=1
```

Incorrect:

```text
GET /api/reservations/client/1
```

Exception:

A nested path can be accepted only when it improves readability and represents a strong domain relation.

Example:

```text
GET /api/clients/{id}/reservations
```

## Final rule

Use query parameters for filtering, searching, sorting and pagination.
