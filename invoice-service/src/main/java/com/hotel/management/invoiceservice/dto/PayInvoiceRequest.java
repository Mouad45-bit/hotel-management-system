package com.hotel.management.invoiceservice.dto;

import com.hotel.management.invoiceservice.entity.PaymentMethod;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;

public record PayInvoiceRequest(
        @NotNull(message = "Payment method is required")
        PaymentMethod paymentMethod,
        String paymentReference,
        LocalDateTime paidAt
) {
}
