package com.hotel.management.housekeepingservice.dto.external;

import com.fasterxml.jackson.annotation.JsonAlias;

import java.time.LocalDate;

public record ReservationSummaryResponse(
        @JsonAlias("id")
        Long reservationId,
        Long roomId,
        String status,
        LocalDate checkOutDate
) {
}
