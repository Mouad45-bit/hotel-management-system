package com.hotel.management.reservationservice.client.dto;

public record FullClientInfo(
        Long id,
        String firstName,
        String lastName,
        String email,
        String phone,
        Boolean active
) {}
