package com.hotel.management.staffservice.dto.external;

public record CreateAuthUserRequest(
        String username,
        String email,
        String password,
        String firstName,
        String lastName,
        String role
) {
}
