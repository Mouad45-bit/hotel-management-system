# Database per Service

## Principle

In the Hotel Management System, each microservice owns its own database.

A service must not directly read or write another service's database.

## Current database

| Service | Database container | Database name | Internal URL |
|---|---|---|---|
| auth-service | db-auth | db_auth | jdbc:mariadb://db-auth:3306/db_auth |
| room-service | db-room | db_room | jdbc:mariadb://db-room:3306/db_room |

## Local development access

When the database runs in Docker and the service runs locally from IntelliJ:

```text
auth-service local  → jdbc:mariadb://localhost:3307/db_auth
room-service local  → jdbc:mariadb://localhost:3308/db_room
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

## Database naming convention

| Microservice         | Database container | Database name   | Volume name          |
|----------------------|--------------------|-----------------|----------------------|
| auth-service         | db-auth            | db_auth         | db-auth-data         |
| room-service         | db-room            | db_room         | db-room-data         |
| client-service       | db-client          | db_client       | db-client-data       |
| reservation-service  | db-reservation     | db_reservation  | db-reservation-data  |
| billing-service      | db-billing         | db_billing      | db-billing-data      |
| housekeeping-service | db-housekeeping    | db_housekeeping | db-housekeeping-data |
| staff-service        | db-staff           | db_staff        | db-staff-data        |
| report-service       | db-report          | db_report       | db-report-data       |

## Rules

- Docker service names use kebab-case: `db-auth`.
- Database names use snake_case: `db_auth`.
- Docker volume names use kebab-case and end with `-data`: `db-auth-data`.
- Application services must use a dedicated database user.
- Application services must not use the database root user.
