package com.hotel.management.staffservice.dto.external;

public record AuthUserResponse(
        Long id,
        String username,
        String email,
        String firstName,
        String lastName,
        String role,
        Boolean active
) {
}
