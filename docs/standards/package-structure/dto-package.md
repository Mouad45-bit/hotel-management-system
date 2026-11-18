# DTO Package

## Objective

The `dto` package contains API request and response objects.

DTO means Data Transfer Object.

DTOs define what the API receives and returns.

## Package path

```text
com.hotel.management.<servicename>.dto
```

Example:

```text
com.hotel.management.roomservice.dto
```

## Responsibilities

DTOs are responsible for:

- defining request payloads
- defining response payloads
- applying input validation annotations
- hiding internal entity structure
- stabilizing the public API contract

## Forbidden responsibilities

DTOs must not:

- contain business logic
- access repositories
- access services
- contain JPA annotations
- represent database relationships directly

## Request DTO example

```java
public record RoomRequest(
        @NotBlank(message = "Room number is required")
        String number,

        @NotNull(message = "Room type is required")
        RoomType type,

        @NotNull(message = "Price per night is required")
        BigDecimal pricePerNight
) {
}
```

## Response DTO example

```java
public record RoomResponse(
        Long id,
        String number,
        RoomType type,
        RoomStatus status,
        BigDecimal pricePerNight
) {
}
```

## Why use DTOs?

DTOs protect the API from internal database changes.

For example, the entity may contain:

```text
createdAt
updatedAt
internalStatus
technical fields
```

But the response can expose only what the client needs.

## Naming convention

Request DTOs should end with:

```text
Request
```

Response DTOs should end with:

```text
Response
```

Examples:

```text
RoomRequest
RoomResponse
ClientRequest
ClientResponse
ReservationRequest
ReservationResponse
```
