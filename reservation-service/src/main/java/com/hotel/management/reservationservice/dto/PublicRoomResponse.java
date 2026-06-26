package com.hotel.management.reservationservice.dto;

import java.math.BigDecimal;

public record PublicRoomResponse(
        Long id,
        String number,
        String type,
        Integer floor,
        BigDecimal pricePerNight,
        Integer capacity,
        String description
) {}
