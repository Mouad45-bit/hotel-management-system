package com.hotel.management.invoiceservice.dto.external;

import java.math.BigDecimal;
import java.time.LocalDate;

public record ReservationSummaryResponse(
        Long reservationId,
        String reservationStatus,
        Long clientId,
        Long roomId,
        LocalDate checkInDate,
        LocalDate checkOutDate,
        BigDecimal pricePerNight
) {
}
