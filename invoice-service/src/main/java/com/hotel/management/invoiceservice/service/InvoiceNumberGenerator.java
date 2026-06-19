package com.hotel.management.invoiceservice.service;

import com.hotel.management.invoiceservice.repository.InvoiceRepository;
import org.springframework.stereotype.Component;

import java.time.Year;

@Component
public class InvoiceNumberGenerator {

    private final InvoiceRepository invoiceRepository;

    public InvoiceNumberGenerator(InvoiceRepository invoiceRepository) {
        this.invoiceRepository = invoiceRepository;
    }

    public String generate() {
        int year = Year.now().getValue();
        long sequence = invoiceRepository.count() + 1;
        String invoiceNumber = format(year, sequence);

        while (invoiceRepository.existsByInvoiceNumber(invoiceNumber)) {
            sequence++;
            invoiceNumber = format(year, sequence);
        }

        return invoiceNumber;
    }

    private String format(int year, long sequence) {
        return "INV-%d-%06d".formatted(year, sequence);
    }
}
