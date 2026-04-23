package com.hotel.management.authservice.dto;

import com.hotel.management.authservice.entity.Role;
import jakarta.validation.constraints.*;
import lombok.Data;

/**
 * Corps de la requête POST /api/auth/register.
 * ## Endpoint réservé aux ADMIN (contrôle via @PreAuthorize dans le controller).
 */
@Data
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must contain between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must contain at least 8 characters")
    private String password;

    @NotNull(message = "Role is mandatory")
    private Role role;
}