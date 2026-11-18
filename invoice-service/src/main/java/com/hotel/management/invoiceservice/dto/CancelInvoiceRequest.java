package com.hotel.management.invoiceservice.dto;

import jakarta.validation.constraints.NotBlank;

public record CancelInvoiceRequest(
        @NotBlank(message = "Cancellation reason is required")
        String reason
) {
}
