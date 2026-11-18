package com.hotel.management.invoiceservice.dto;

import com.hotel.management.invoiceservice.entity.InvoiceLineType;

import java.math.BigDecimal;

public record InvoiceLineResponse(
        Long id,
        InvoiceLineType type,
        String description,
        Integer quantity,
        BigDecimal unitPrice,
        BigDecimal lineTotal
) {
}
