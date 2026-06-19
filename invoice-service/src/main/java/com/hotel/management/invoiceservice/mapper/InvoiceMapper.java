package com.hotel.management.invoiceservice.mapper;

import com.hotel.management.invoiceservice.dto.InvoiceLineResponse;
import com.hotel.management.invoiceservice.dto.InvoiceResponse;
import com.hotel.management.invoiceservice.entity.Invoice;
import com.hotel.management.invoiceservice.entity.InvoiceLine;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InvoiceMapper {

    public InvoiceResponse toResponse(Invoice invoice) {
        List<InvoiceLineResponse> lines = invoice.getLines()
                .stream()
                .map(this::toLineResponse)
                .toList();

        return new InvoiceResponse(
                invoice.getId(),
                invoice.getInvoiceNumber(),
                invoice.getReservationId(),
                invoice.getClientId(),
                invoice.getClientFullName(),
                invoice.getRoomId(),
                invoice.getRoomNumber(),
                invoice.getCheckInDate(),
                invoice.getCheckOutDate(),
                invoice.getNights(),
                invoice.getPricePerNight(),
                invoice.getSubtotalAmount(),
                invoice.getTaxRate(),
                invoice.getTaxAmount(),
                invoice.getTotalAmount(),
                invoice.getStatus(),
                invoice.getPaymentMethod(),
                invoice.getPaymentReference(),
                invoice.getNotes(),
                invoice.getCancellationReason(),
                invoice.getRefundReason(),
                invoice.getIssuedAt(),
                invoice.getPaidAt(),
                invoice.getCancelledAt(),
                invoice.getRefundedAt(),
                invoice.getCreatedAt(),
                invoice.getUpdatedAt(),
                lines
        );
    }

    public InvoiceLineResponse toLineResponse(InvoiceLine line) {
        return new InvoiceLineResponse(
                line.getId(),
                line.getType(),
                line.getDescription(),
                line.getQuantity(),
                line.getUnitPrice(),
                line.getLineTotal()
        );
    }
}
