# Config Package

## Objective

The `config` package contains Spring configuration classes.

It groups technical configuration that supports the microservice.

## Package path

```text
com.hotel.management.<servicename>.config
```

Example:

```text
com.hotel.management.roomservice.config
```

## Responsibilities

The config package can contain:

- security configuration
- CORS configuration
- OpenAPI / Swagger configuration
- REST client configuration
- bean definitions
- object mapper configuration
- service-specific technical settings

## Forbidden responsibilities

Configuration classes must not contain:

- business logic
- controller endpoints
- repository queries
- DTO mapping
- domain calculations

## Example: CORS configuration

```java
@Configuration
public class CorsConfig {

    // CORS configuration for the service if needed.
}
```

## Example: REST client configuration

```java
@Configuration
public class RestClientConfig {

    @Bean
    public RestClient restClient() {
        return RestClient.builder().build();
    }
}
```

## Example: OpenAPI configuration

```java
@Configuration
public class OpenApiConfig {

    // API documentation configuration.
}
```

## Naming convention

Configuration classes must end with:

```text
Config
```

Examples:

```text
SecurityConfig
CorsConfig
OpenApiConfig
RestClientConfig
```

## Rule

Only technical Spring configuration belongs in this package.

Business decisions must stay in the service layer.
