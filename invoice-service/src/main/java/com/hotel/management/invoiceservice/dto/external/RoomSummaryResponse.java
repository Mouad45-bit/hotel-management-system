package com.hotel.management.invoiceservice.dto.external;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.math.BigDecimal;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RoomSummaryResponse(
        @JsonAlias("id") Long roomId,
        @JsonAlias("number") String roomNumber,
        BigDecimal pricePerNight
) {
}
