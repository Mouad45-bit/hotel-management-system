# Entity Package

## Objective

The `entity` package contains persistence objects.

Entities represent database tables managed by the microservice.

## Package path

```text
com.hotel.management.<servicename>.entity
```

Example:

```text
com.hotel.management.roomservice.entity
```

## Responsibilities

Entities are responsible for:

- representing database tables
- defining JPA mappings
- defining relationships inside the same service database
- storing persistence-related fields
- defining lifecycle hooks such as `@PrePersist` and `@PreUpdate`

## Forbidden responsibilities

Entities must not:

- expose API contracts directly
- contain HTTP annotations
- call repositories
- call services
- contain complex business workflows
- represent tables from another microservice database

## Example

```java
@Entity
@Table(name = "rooms")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Room {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String number;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RoomStatus status;

    private BigDecimal pricePerNight;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
```

## Entity vs DTO

Entities are internal persistence models.

DTOs are external API models.

Do not expose entities directly in controllers unless the service is extremely simple and the decision is explicitly accepted.

Preferred pattern:

```text
Entity → Mapper → Response DTO
```

## Naming convention

Entity classes should use business names.

Examples:

```text
Room
Client
Reservation
Invoice
HousekeepingTask
Employee
```
