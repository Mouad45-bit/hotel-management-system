package com.hotel.management.staffservice.dto;

import com.hotel.management.staffservice.entity.Department;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateEmployeeRequest(
        @NotBlank(message = "First name is required")
        @Size(max = 80, message = "First name must not exceed 80 characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(max = 80, message = "Last name must not exceed 80 characters")
        String lastName,

        @Email(message = "Email must be valid")
        @Size(max = 160, message = "Email must not exceed 160 characters")
        String email,

        @Size(max = 40, message = "Phone must not exceed 40 characters")
        String phone,

        @NotBlank(message = "CIN is required")
        @Size(max = 40, message = "CIN must not exceed 40 characters")
        String cin,

        @NotNull(message = "Department is required")
        Department department
) {
}
