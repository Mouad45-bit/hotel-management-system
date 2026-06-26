package com.hotel.management.reservationservice.client.dto;

public record ClientCreateRequest(
        String firstName,
        String lastName,
        String email,
        String phone
) {}
