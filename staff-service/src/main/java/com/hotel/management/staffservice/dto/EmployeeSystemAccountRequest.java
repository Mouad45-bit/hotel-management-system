package com.hotel.management.staffservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmployeeSystemAccountRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must contain between 3 and 50 characters")
        String username,

        @NotBlank(message = "Password is required")
        @Size(min = 6, message = "Password must contain at least 6 characters")
        String password,

        @NotBlank(message = "Role is required")
        String role
) {
}
