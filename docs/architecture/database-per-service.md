# Database per Service

## Principle

In the Hotel Management System, each microservice owns its own database.

A service must not directly read or write another service's database.

## Current database

| Service | Database container | Database name | Internal URL |
|---|---|---|---|
| auth-service | db-auth | db_auth | jdbc:mariadb://db-auth:3306/db_auth |

## Local development access

When the database runs in Docker and the service runs locally from IntelliJ:

```text
jdbc:mariadb://localhost:3307/db_auth
```

## Docker access

When both the service and the database run in Docker:

```text
jdbc:mariadb://db-auth:3306/db_auth
```

## Why this rule matters

Each microservice must control its own data model.

For example:

- auth-service manages users, credentials and roles.
- room-service will manage rooms.
- reservation-service will manage reservations.
- billing-service will manage invoices.

Other services must communicate through APIs, not by directly accessing another database.

## Forbidden pattern

```text
reservation-service → direct SQL query → db-auth
```

## Correct pattern

```text
reservation-service → REST/API call → auth-service
```

