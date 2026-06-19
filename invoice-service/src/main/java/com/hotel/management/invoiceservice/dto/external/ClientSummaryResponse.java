package com.hotel.management.invoiceservice.dto.external;

public record ClientSummaryResponse(
        Long clientId,
        String fullName
) {
}
