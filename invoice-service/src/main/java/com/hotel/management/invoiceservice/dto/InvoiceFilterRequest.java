package com.hotel.management.invoiceservice.dto;

import com.hotel.management.invoiceservice.entity.InvoiceStatus;

import java.time.LocalDate;

public record InvoiceFilterRequest(
        String number,
        InvoiceStatus status,
        Long clientId,
        Long reservationId,
        LocalDate from,
        LocalDate to,
        Integer page,
        Integer size,
        String sort
) {
}
