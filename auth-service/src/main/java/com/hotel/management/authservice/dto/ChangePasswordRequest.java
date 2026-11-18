package com.hotel.management.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "L'ancien mot de passe est requis")
        String oldPassword,

        @NotBlank(message = "Le nouveau mot de passe est requis")
        @Size(min = 6, message = "Le nouveau mot de passe doit contenir au moins 6 caractères")
        String newPassword
) {}
