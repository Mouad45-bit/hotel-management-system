package com.hotel.management.invoiceservice.exception;

public class InvoiceConflictException extends RuntimeException {

    public InvoiceConflictException(String message) {
        super(message);
    }
}
