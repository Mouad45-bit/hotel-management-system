package com.hotel.management.reservationservice.client.dto;

import java.math.BigDecimal;

public record RoomInfo(
        Long id,
        String number,
        String status,
        BigDecimal pricePerNight,
        Boolean active
) {}
