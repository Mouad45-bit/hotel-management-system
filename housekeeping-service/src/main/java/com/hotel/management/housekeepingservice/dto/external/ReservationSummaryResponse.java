package com.hotel.management.housekeepingservice.dto.external;

import java.time.LocalDate;

public record ReservationSummaryResponse(
        Long reservationId,
        Long roomId,
        String status,
        LocalDate checkOutDate
) {
}
