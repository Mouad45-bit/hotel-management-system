package com.hotel.management.invoiceservice.dto;

import java.time.LocalDate;

public record IssueInvoiceRequest(
        LocalDate issueDate
) {
}
