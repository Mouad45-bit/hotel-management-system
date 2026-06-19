package com.hotel.management.invoiceservice.repository;

import com.hotel.management.invoiceservice.entity.Invoice;
import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface InvoiceRepository extends JpaRepository<Invoice, Long>, JpaSpecificationExecutor<Invoice> {

    boolean existsByInvoiceNumber(String invoiceNumber);

    Optional<Invoice> findByInvoiceNumber(String invoiceNumber);

    List<Invoice> findByClientId(Long clientId);

    Optional<Invoice> findByReservationId(Long reservationId);

    List<Invoice> findByStatus(InvoiceStatus status);

    boolean existsByReservationIdAndStatusIn(Long reservationId, Collection<InvoiceStatus> statuses);
}
