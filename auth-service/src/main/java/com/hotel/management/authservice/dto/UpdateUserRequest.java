package com.hotel.management.authservice.dto;

import jakarta.validation.constraints.Email;

public record UpdateUserRequest(
        @Email(message = "L'email doit être valide")
        String email,
        String firstName,
        String lastName,
        String role
) {}
