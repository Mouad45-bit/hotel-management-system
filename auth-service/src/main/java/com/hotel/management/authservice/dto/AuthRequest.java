package com.hotel.management.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Corps de la requête POST /api/auth/login.
 * @NotBlank déclenche une 400 Bad Request si le champ est vide ou null.
 */
@Data
public class AuthRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
}