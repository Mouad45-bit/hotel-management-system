package com.hotel.management.invoiceservice.repository;

import com.hotel.management.invoiceservice.entity.InvoiceLine;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvoiceLineRepository extends JpaRepository<InvoiceLine, Long> {
}
