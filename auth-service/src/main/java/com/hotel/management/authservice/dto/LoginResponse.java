package com.hotel.management.authservice.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        String tokenType
) {}
