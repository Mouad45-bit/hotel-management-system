package com.hotel.management.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank(message = "Le nom d'utilisateur est requis")
        @Size(min = 3, max = 50, message = "Le nom d'utilisateur doit contenir entre 3 et 50 caractères")
        String username,

        @Email(message = "L'email doit être valide")
        String email,

        @NotBlank(message = "Le mot de passe est requis")
        @Size(min = 6, message = "Le mot de passe doit contenir au moins 6 caractères")
        String password,

        @NotBlank(message = "Le prénom est requis")
        String firstName,

        @NotBlank(message = "Le nom est requis")
        String lastName,

        @NotNull(message = "Le rôle est requis")
        String role
) {}
