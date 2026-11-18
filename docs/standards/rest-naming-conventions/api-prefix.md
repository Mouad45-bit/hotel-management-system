# API Prefix Convention

## Objective

All business routes in HMS must start with `/api`.

## Rule

```text
/api
```

is the mandatory prefix for all external business APIs.

## Correct examples

```text
/api/auth/login
/api/rooms
/api/clients
/api/reservations
/api/billing
/api/housekeeping
/api/staff
/api/reports
```

## Incorrect examples

```text
/auth/login
/rooms
/clients
/reservations
/billing
```

## Why use `/api`?

The `/api` prefix clearly separates backend API routes from:

- frontend routes
- static resources
- actuator endpoints
- internal infrastructure routes

## Technical endpoints exception

Spring Boot Actuator endpoints do not use `/api`.

Correct:

```text
/actuator/health
/actuator/info
```

Incorrect:

```text
/api/actuator/health
```

## API Gateway rule

The API Gateway must route external business traffic using `/api/**`.

Example:

```text
/api/auth/**         → auth-service
/api/rooms/**        → room-service
/api/clients/**      → client-service
/api/reservations/** → reservation-service
```

## Final rule

Every controller exposing business operations must use `/api` as route prefix.
