package com.hotel.management.clientservice.dto.external;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientReservationResponse(
        Long id,
        Long roomId,
        Long clientId,
        LocalDate checkInDate,
        LocalDate checkOutDate,
        String status,
        BigDecimal totalPrice,
        String notes,
        String reference,
        Boolean active,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
