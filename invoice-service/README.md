# invoice-service

Invoice management service for the Hotel Management System.

## Responsibility

This service owns invoice data and lifecycle actions:

- generate an invoice from a checked-out reservation;
- list and retrieve invoices;
- issue, pay, cancel and refund invoices;
- expose invoice data required by the frontend printable preview.

## Local run

```bash
mvn -f invoice-service/pom.xml spring-boot:run
```

## Docker run

```bash
docker compose up --build -d invoice-service
```

## Healthcheck

```bash
curl http://localhost:8085/actuator/health
```
