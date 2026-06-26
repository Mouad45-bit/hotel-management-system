package com.hotel.management.reservationservice.client.dto;

import java.math.BigDecimal;

public record FullRoomInfo(
        Long id,
        String number,
        Integer floor,
        String type,
        BigDecimal pricePerNight,
        Integer capacity,
        String status,
        String description,
        Boolean active
) {}
