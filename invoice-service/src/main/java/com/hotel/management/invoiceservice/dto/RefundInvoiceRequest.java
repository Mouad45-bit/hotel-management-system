package com.hotel.management.invoiceservice.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.LocalDateTime;

public record RefundInvoiceRequest(
        @NotBlank(message = "Refund reason is required")
        String reason,
        String paymentReference,
        LocalDateTime refundedAt
) {
}
