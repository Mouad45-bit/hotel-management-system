package com.hotel.management.staffservice.service.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hotel.management.staffservice.dto.CreateEmployeeRequest;
import com.hotel.management.staffservice.dto.EmployeeSystemAccountRequest;
import com.hotel.management.staffservice.dto.external.AuthUserResponse;
import com.hotel.management.staffservice.dto.external.CreateAuthUserRequest;
import com.hotel.management.staffservice.exception.ExternalAuthServiceException;
import com.hotel.management.staffservice.exception.ExternalAuthValidationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class AuthUserClient {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String authServiceUrl;

    public AuthUserClient(
            RestClient.Builder restClientBuilder,
            ObjectMapper objectMapper,
            @Value("${auth.service.url:${AUTH_SERVICE_URL:http://localhost:8081}}") String authServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.objectMapper = objectMapper;
        this.authServiceUrl = authServiceUrl;
    }

    public AuthUserResponse createUser(String authorizationHeader, CreateEmployeeRequest employeeRequest) {
        assertAuthorizationHeader(authorizationHeader);

        EmployeeSystemAccountRequest account = employeeRequest.systemAccount();
        CreateAuthUserRequest request = new CreateAuthUserRequest(
                account.username().trim(),
                cleanOptional(employeeRequest.email()),
                account.password(),
                employeeRequest.firstName().trim(),
                employeeRequest.lastName().trim(),
                account.role()
        );

        try {
            return restClient.post()
                    .uri(authServiceUrl + "/api/auth/users")
                    .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                    .body(request)
                    .retrieve()
                    .body(AuthUserResponse.class);
        } catch (HttpClientErrorException.BadRequest exception) {
            throw buildValidationException(exception);
        } catch (HttpClientErrorException exception) {
            throw buildServiceException(exception);
        }
    }

    public void deactivateUser(String authorizationHeader, Long userId) {
        assertAuthorizationHeader(authorizationHeader);

        try {
            restClient.patch()
                    .uri(authServiceUrl + "/api/auth/users/{id}/deactivate", userId)
                    .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                    .retrieve()
                    .toBodilessEntity();
        } catch (HttpClientErrorException exception) {
            throw buildServiceException(exception);
        }
    }

    private void assertAuthorizationHeader(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            throw new ExternalAuthServiceException(
                    HttpStatus.UNAUTHORIZED,
                    "AUTHENTICATION_REQUIRED",
                    "Authentification admin requise pour créer un compte système."
            );
        }
    }

    private ExternalAuthValidationException buildValidationException(HttpClientErrorException exception) {
        try {
            JsonNode body = objectMapper.readTree(exception.getResponseBodyAsString());
            JsonNode fieldErrorsNode = body.get("fieldErrors");
            if (fieldErrorsNode != null && fieldErrorsNode.isObject()) {
                Map<String, String> authFieldErrors = objectMapper.convertValue(
                        fieldErrorsNode,
                        new TypeReference<>() {}
                );
                Map<String, String> staffFieldErrors = new LinkedHashMap<>();
                authFieldErrors.forEach((field, message) -> staffFieldErrors.put(mapAuthField(field), message));
                return new ExternalAuthValidationException(staffFieldErrors);
            }
        } catch (Exception ignored) {
            // Fall through to a field-level generic account error.
        }

        return new ExternalAuthValidationException(Map.of("systemAccount", extractMessage(exception)));
    }

    private ExternalAuthServiceException buildServiceException(HttpClientErrorException exception) {
        HttpStatus status = HttpStatus.resolve(exception.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.BAD_REQUEST;
        }

        return new ExternalAuthServiceException(
                status,
                status == HttpStatus.CONFLICT ? "AUTH_USER_ALREADY_EXISTS" : "AUTH_USER_CREATION_FAILED",
                extractMessage(exception)
        );
    }

    private String extractMessage(HttpClientErrorException exception) {
        try {
            JsonNode body = objectMapper.readTree(exception.getResponseBodyAsString());
            JsonNode message = body.get("message");
            if (message != null && !message.asText().isBlank()) {
                return message.asText();
            }
        } catch (Exception ignored) {
            // Keep a stable fallback below.
        }

        return "Unable to create auth user";
    }

    private String mapAuthField(String field) {
        return switch (field) {
            case "username" -> "systemAccount.username";
            case "password" -> "systemAccount.password";
            case "role" -> "systemAccount.role";
            case "firstName" -> "firstName";
            case "lastName" -> "lastName";
            case "email" -> "email";
            default -> "systemAccount." + field;
        };
    }

    private String cleanOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        return value.trim();
    }
}
