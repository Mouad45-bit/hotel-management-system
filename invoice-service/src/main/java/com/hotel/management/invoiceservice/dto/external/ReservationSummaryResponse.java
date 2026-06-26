package com.hotel.management.invoiceservice.dto.external;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDate;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ReservationSummaryResponse(
        @JsonAlias("id") Long reservationId,
        @JsonAlias("status") String reservationStatus,
        Long clientId,
        Long roomId,
        LocalDate checkInDate,
        LocalDate checkOutDate
) {
}
