package com.hotel.management.reservationservice.client.dto;

public record ClientInfo(
        Long id,
        String firstName,
        String lastName,
        Boolean active
) {}
