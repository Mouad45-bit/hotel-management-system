package com.hotel.management.invoiceservice.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;

import java.math.BigDecimal;

public record CreateInvoiceFromReservationRequest(
        @NotNull(message = "Tax rate is required")
        @DecimalMin(value = "0.00", message = "Tax rate must be greater than or equal to 0")
        BigDecimal taxRate,
        String notes
) {
}
