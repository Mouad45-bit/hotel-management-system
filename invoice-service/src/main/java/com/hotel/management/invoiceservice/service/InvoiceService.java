package com.hotel.management.invoiceservice.service;

import com.hotel.management.invoiceservice.dto.CancelInvoiceRequest;
import com.hotel.management.invoiceservice.dto.CreateInvoiceFromReservationRequest;
import com.hotel.management.invoiceservice.dto.IssueInvoiceRequest;
import com.hotel.management.invoiceservice.dto.PayInvoiceRequest;
import com.hotel.management.invoiceservice.dto.RefundInvoiceRequest;
import com.hotel.management.invoiceservice.dto.InvoiceResponse;
import com.hotel.management.invoiceservice.dto.PageResponse;
import com.hotel.management.invoiceservice.dto.external.ClientSummaryResponse;
import com.hotel.management.invoiceservice.dto.external.ReservationSummaryResponse;
import com.hotel.management.invoiceservice.dto.external.RoomSummaryResponse;
import com.hotel.management.invoiceservice.entity.Invoice;
import com.hotel.management.invoiceservice.entity.InvoiceLine;
import com.hotel.management.invoiceservice.entity.InvoiceLineType;
import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import com.hotel.management.invoiceservice.exception.InvoiceBusinessException;
import com.hotel.management.invoiceservice.exception.InvoiceConflictException;
import com.hotel.management.invoiceservice.exception.InvoiceNotFoundException;
import com.hotel.management.invoiceservice.mapper.InvoiceMapper;
import com.hotel.management.invoiceservice.repository.InvoiceRepository;
import com.hotel.management.invoiceservice.service.client.ClientClient;
import com.hotel.management.invoiceservice.service.client.ReservationClient;
import com.hotel.management.invoiceservice.service.client.RoomClient;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

@Service
public class InvoiceService {

    private static final List<InvoiceStatus> ACTIVE_STATUSES = List.of(
            InvoiceStatus.DRAFT,
            InvoiceStatus.ISSUED,
            InvoiceStatus.PAID
    );
    private static final BigDecimal ONE_HUNDRED = BigDecimal.valueOf(100);

    private final InvoiceRepository invoiceRepository;
    private final InvoiceNumberGenerator invoiceNumberGenerator;
    private final InvoiceMapper invoiceMapper;
    private final ReservationClient reservationClient;
    private final ClientClient clientClient;
    private final RoomClient roomClient;

    public InvoiceService(
            InvoiceRepository invoiceRepository,
            InvoiceNumberGenerator invoiceNumberGenerator,
            InvoiceMapper invoiceMapper,
            ReservationClient reservationClient,
            ClientClient clientClient,
            RoomClient roomClient
    ) {
        this.invoiceRepository = invoiceRepository;
        this.invoiceNumberGenerator = invoiceNumberGenerator;
        this.invoiceMapper = invoiceMapper;
        this.reservationClient = reservationClient;
        this.clientClient = clientClient;
        this.roomClient = roomClient;
    }

    @Transactional(readOnly = true)
    public PageResponse<InvoiceResponse> findAll(String number, InvoiceStatus status, Long clientId, Long reservationId, LocalDate from, LocalDate to, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(normalizePage(page), normalizeSize(size), parseSort(sort));
        Page<InvoiceResponse> invoices = invoiceRepository.findAll(buildSpecification(number, status, clientId, reservationId, from, to), pageable)
                .map(invoiceMapper::toResponse);

        return new PageResponse<>(
                invoices.getContent(),
                invoices.getNumber(),
                invoices.getSize(),
                invoices.getTotalElements(),
                invoices.getTotalPages(),
                invoices.isLast()
        );
    }

    @Transactional(readOnly = true)
    public InvoiceResponse findById(Long id) {
        return invoiceRepository.findById(id)
                .map(invoiceMapper::toResponse)
                .orElseThrow(() -> new InvoiceNotFoundException("Invoice not found with id: " + id));
    }

    @Transactional(readOnly = true)
    public InvoiceResponse findByNumber(String number) {
        return invoiceRepository.findByInvoiceNumber(number)
                .map(invoiceMapper::toResponse)
                .orElseThrow(() -> new InvoiceNotFoundException("Invoice not found with number: " + number));
    }

    @Transactional(readOnly = true)
    public List<InvoiceResponse> findByClientId(Long clientId) {
        return invoiceRepository.findByClientId(clientId)
                .stream()
                .map(invoiceMapper::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public InvoiceResponse findByReservationId(Long reservationId) {
        return invoiceRepository.findByReservationId(reservationId)
                .map(invoiceMapper::toResponse)
                .orElseThrow(() -> new InvoiceNotFoundException("Invoice not found for reservation: " + reservationId));
    }

    @Transactional
    public InvoiceResponse generateFromReservation(Long reservationId, CreateInvoiceFromReservationRequest request) {
        if (invoiceRepository.existsByReservationIdAndStatusIn(reservationId, ACTIVE_STATUSES)) {
            throw new InvoiceConflictException("An active invoice already exists for reservation: " + reservationId);
        }

        ReservationSummaryResponse reservation = reservationClient.findSummaryById(reservationId);
        ClientSummaryResponse client = clientClient.findSummaryById(reservation.clientId());
        RoomSummaryResponse room = roomClient.findSummaryById(reservation.roomId());

        if (!"CHECKED_OUT".equals(reservation.reservationStatus())) {
            throw new InvoiceBusinessException("Reservation must be CHECKED_OUT before invoice generation");
        }

        int nights = calculateNights(reservation.checkInDate(), reservation.checkOutDate());
        BigDecimal pricePerNight = room.pricePerNight().setScale(2, RoundingMode.HALF_UP);
        BigDecimal subtotalAmount = pricePerNight
                .multiply(BigDecimal.valueOf(nights))
                .setScale(2, RoundingMode.HALF_UP);
        BigDecimal taxAmount = subtotalAmount
                .multiply(request.taxRate())
                .divide(ONE_HUNDRED, 2, RoundingMode.HALF_UP);
        BigDecimal totalAmount = subtotalAmount.add(taxAmount).setScale(2, RoundingMode.HALF_UP);

        Invoice invoice = new Invoice();
        invoice.setInvoiceNumber(invoiceNumberGenerator.generate());
        invoice.setReservationId(reservation.reservationId());
        invoice.setClientId(reservation.clientId());
        invoice.setClientFullName(client.fullName());
        invoice.setRoomId(reservation.roomId());
        invoice.setRoomNumber(room.roomNumber());
        invoice.setCheckInDate(reservation.checkInDate());
        invoice.setCheckOutDate(reservation.checkOutDate());
        invoice.setNights(nights);
        invoice.setPricePerNight(pricePerNight);
        invoice.setSubtotalAmount(subtotalAmount);
        invoice.setTaxRate(request.taxRate().setScale(2, RoundingMode.HALF_UP));
        invoice.setTaxAmount(taxAmount);
        invoice.setTotalAmount(totalAmount);
        invoice.setStatus(InvoiceStatus.DRAFT);
        invoice.setNotes(request.notes());

        InvoiceLine roomStayLine = new InvoiceLine();
        roomStayLine.setType(InvoiceLineType.ROOM_STAY);
        roomStayLine.setDescription("Sejour chambre %s - %d nuit(s)".formatted(room.roomNumber(), nights));
        roomStayLine.setQuantity(nights);
        roomStayLine.setUnitPrice(pricePerNight);
        roomStayLine.setLineTotal(subtotalAmount);
        invoice.addLine(roomStayLine);

        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    
    @Transactional
    public InvoiceResponse issue(Long id, IssueInvoiceRequest request) {
        Invoice invoice = getInvoiceEntity(id);
        requireStatus(invoice, InvoiceStatus.DRAFT, "Only DRAFT invoices can be issued");
        invoice.setStatus(InvoiceStatus.ISSUED);
        invoice.setIssuedAt(request.issueDate() != null ? request.issueDate().atStartOfDay() : LocalDateTime.now());
        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    
    @Transactional
    public InvoiceResponse pay(Long id, PayInvoiceRequest request) {
        Invoice invoice = getInvoiceEntity(id);
        requireStatus(invoice, InvoiceStatus.ISSUED, "Only ISSUED invoices can be paid");
        invoice.setStatus(InvoiceStatus.PAID);
        invoice.setPaymentMethod(request.paymentMethod());
        invoice.setPaymentReference(request.paymentReference());
        invoice.setPaidAt(request.paidAt() != null ? request.paidAt() : LocalDateTime.now());
        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    
    @Transactional
    public InvoiceResponse cancel(Long id, CancelInvoiceRequest request) {
        Invoice invoice = getInvoiceEntity(id);
        if (invoice.getStatus() != InvoiceStatus.DRAFT && invoice.getStatus() != InvoiceStatus.ISSUED) {
            throw new InvoiceBusinessException("Only DRAFT or ISSUED invoices can be cancelled");
        }
        invoice.setStatus(InvoiceStatus.CANCELLED);
        invoice.setCancellationReason(request.reason());
        invoice.setCancelledAt(LocalDateTime.now());
        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    
    @Transactional
    public InvoiceResponse refund(Long id, RefundInvoiceRequest request) {
        Invoice invoice = getInvoiceEntity(id);
        requireStatus(invoice, InvoiceStatus.PAID, "Only PAID invoices can be refunded");
        invoice.setStatus(InvoiceStatus.REFUNDED);
        invoice.setRefundReason(request.reason());
        invoice.setPaymentReference(request.paymentReference() != null ? request.paymentReference() : invoice.getPaymentReference());
        invoice.setRefundedAt(request.refundedAt() != null ? request.refundedAt() : LocalDateTime.now());
        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    private Invoice getInvoiceEntity(Long id) {
        return invoiceRepository.findById(id)
                .orElseThrow(() -> new InvoiceNotFoundException("Invoice not found with id: " + id));
    }

    private void requireStatus(Invoice invoice, InvoiceStatus expectedStatus, String message) {
        if (invoice.getStatus() != expectedStatus) {
            throw new InvoiceBusinessException(message);
        }
    }

    private Specification<Invoice> buildSpecification(String number, InvoiceStatus status, Long clientId, Long reservationId, LocalDate from, LocalDate to) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (number != null && !number.isBlank()) {
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("invoiceNumber")), "%" + number.toLowerCase() + "%"));
            }
            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }
            if (clientId != null) {
                predicates.add(criteriaBuilder.equal(root.get("clientId"), clientId));
            }
            if (reservationId != null) {
                predicates.add(criteriaBuilder.equal(root.get("reservationId"), reservationId));
            }
            if (from != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("createdAt"), from.atStartOfDay()));
            }
            if (to != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("createdAt"), to.atTime(23, 59, 59)));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private int normalizePage(int page) {
        return Math.max(page, 0);
    }

    private int normalizeSize(int size) {
        if (size <= 0) {
            return 10;
        }
        return Math.min(size, 100);
    }

    private Sort parseSort(String sort) {
        if (sort == null || sort.isBlank()) {
            return Sort.by(Sort.Direction.DESC, "createdAt");
        }

        String[] parts = sort.split(",");
        String property = parts[0].isBlank() ? "createdAt" : parts[0];
        Sort.Direction direction = parts.length > 1 && "asc".equalsIgnoreCase(parts[1])
                ? Sort.Direction.ASC
                : Sort.Direction.DESC;
        return Sort.by(direction, property);
    }

    private int calculateNights(LocalDate checkInDate, LocalDate checkOutDate) {
        long nights = ChronoUnit.DAYS.between(checkInDate, checkOutDate);
        if (nights <= 0) {
            throw new InvoiceBusinessException("Reservation check-out date must be after check-in date");
        }
        return Math.toIntExact(nights);
    }
}
