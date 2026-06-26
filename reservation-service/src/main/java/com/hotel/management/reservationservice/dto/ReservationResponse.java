package com.hotel.management.reservationservice.dto;

import com.hotel.management.reservationservice.entity.ReservationStatus;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

public record ReservationResponse(
        Long id,
        Long roomId,
        Long clientId,
        LocalDate checkInDate,
        LocalDate checkOutDate,
        ReservationStatus status,
        BigDecimal totalPrice,
        String notes,
        String reference,
        Boolean active,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
