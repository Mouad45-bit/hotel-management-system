# Non-root User Convention

## Objective

HMS containers must not run Spring Boot applications as `root`.

## Standard user

Every service must use:

```text
hotel
```

## Dockerfile commands

```dockerfile
RUN addgroup -S hotel \
    && adduser -S hotel -G hotel
```

Then the application jar ownership must be assigned to this user:

```dockerfile
RUN chown hotel:hotel app.jar
```

Finally, the runtime user must be switched:

```dockerfile
USER hotel
```

## Why not run as root?

Running as root inside a container increases security risk.

If an attacker exploits the application, running as a non-root user reduces what the process can do inside the container.

## Correct pattern

```dockerfile
RUN addgroup -S hotel \
    && adduser -S hotel -G hotel

COPY --from=builder /app/target/*.jar app.jar

RUN chown hotel:hotel app.jar

USER hotel
```

## Incorrect pattern

```dockerfile
COPY --from=builder /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
```

In the incorrect pattern, the application runs as the default user, usually root.

## Final rule

Every HMS service Dockerfile must create and use the `hotel` non-root user.
