package com.hotel.management.invoiceservice.controller;

import com.hotel.management.invoiceservice.dto.InvoiceResponse;
import com.hotel.management.invoiceservice.dto.PageResponse;
import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import com.hotel.management.invoiceservice.service.InvoiceService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {

    private final InvoiceService invoiceService;

    public InvoiceController(InvoiceService invoiceService) {
        this.invoiceService = invoiceService;
    }

    @GetMapping
    public PageResponse<InvoiceResponse> findAll(
            @RequestParam(required = false) String number,
            @RequestParam(required = false) InvoiceStatus status,
            @RequestParam(required = false) Long clientId,
            @RequestParam(required = false) Long reservationId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt,desc") String sort
    ) {
        return invoiceService.findAll(number, status, clientId, reservationId, from, to, page, size, sort);
    }

    @GetMapping("/{id}")
    public InvoiceResponse findById(@PathVariable Long id) {
        return invoiceService.findById(id);
    }

    @GetMapping("/number/{number}")
    public InvoiceResponse findByNumber(@PathVariable String number) {
        return invoiceService.findByNumber(number);
    }

    @GetMapping("/client/{clientId}")
    public List<InvoiceResponse> findByClientId(@PathVariable Long clientId) {
        return invoiceService.findByClientId(clientId);
    }

    @GetMapping("/reservation/{reservationId}")
    public InvoiceResponse findByReservationId(@PathVariable Long reservationId) {
        return invoiceService.findByReservationId(reservationId);
    }

    @GetMapping("/ping")
    public Map<String, String> ping() {
        return Map.of("service", "invoice-service", "status", "UP");
    }
}
