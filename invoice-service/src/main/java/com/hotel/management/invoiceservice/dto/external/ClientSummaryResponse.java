package com.hotel.management.invoiceservice.dto.external;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientSummaryResponse(
        Long clientId,
        String fullName
) {
}
