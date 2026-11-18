package com.hotel.management.clientservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Past;

import java.time.LocalDate;

public record UpdateClientRequest(

    @NotBlank(message = "First name is required")
    String firstName,

    @NotBlank(message = "Last name is required")
    String lastName,

    @Email(message = "Email must be valid")
    String email,

    String phone,

    String cin,

    String passportNumber,

    String nationality,

    String address,

    @Past(message = "Birth date must be in the past")
    LocalDate birthDate
) {}
