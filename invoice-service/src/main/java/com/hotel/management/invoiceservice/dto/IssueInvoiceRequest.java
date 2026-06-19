package com.hotel.management.invoiceservice.dto;

import java.time.LocalDateTime;

public record IssueInvoiceRequest(
        LocalDateTime issueDate
) {
}
