package com.hotel.management.invoiceservice.dto;

import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import com.hotel.management.invoiceservice.entity.PaymentMethod;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public record InvoiceResponse(
        Long id,
        String invoiceNumber,
        Long reservationId,
        Long clientId,
        String clientFullName,
        Long roomId,
        String roomNumber,
        LocalDate checkInDate,
        LocalDate checkOutDate,
        Integer nights,
        BigDecimal pricePerNight,
        BigDecimal subtotalAmount,
        BigDecimal taxRate,
        BigDecimal taxAmount,
        BigDecimal totalAmount,
        InvoiceStatus status,
        PaymentMethod paymentMethod,
        String paymentReference,
        String notes,
        String cancellationReason,
        String refundReason,
        LocalDateTime issuedAt,
        LocalDateTime paidAt,
        LocalDateTime cancelledAt,
        LocalDateTime refundedAt,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        List<InvoiceLineResponse> lines
) {
}
