package com.hotel.management.reservationservice.dto;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

public record PublicBookingResponse(
        String reference,
        String guestName,
        String guestEmail,
        String roomNumber,
        String roomType,
        LocalDate checkInDate,
        LocalDate checkOutDate,
        long nights,
        BigDecimal totalPrice,
        String status,
        String specialRequests,
        LocalDateTime createdAt
) {}
