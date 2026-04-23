package com.hotel.management.authservice.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Réponse retournée après un login ou register réussi.
 *
 *  accessToken → JWT court (24h), à envoyer dans chaque requête API
 *  refreshToken → JWT long (7j), uniquement pour /api/auth/refresh
 *  expiresIn → durée de vie du accessToken en secondes (pour le frontend)
 */
@Data
@Builder
public class AuthResponse {

    private String accessToken;
    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private long expiresIn;
    private String username;
    private String role;
}