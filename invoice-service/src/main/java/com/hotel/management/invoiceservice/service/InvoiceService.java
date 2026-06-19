package com.hotel.management.invoiceservice.service;

import com.hotel.management.invoiceservice.dto.CreateInvoiceFromReservationRequest;
import com.hotel.management.invoiceservice.dto.InvoiceResponse;
import com.hotel.management.invoiceservice.entity.Invoice;
import com.hotel.management.invoiceservice.entity.InvoiceLine;
import com.hotel.management.invoiceservice.entity.InvoiceLineType;
import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import com.hotel.management.invoiceservice.mapper.InvoiceMapper;
import com.hotel.management.invoiceservice.repository.InvoiceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
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

    public InvoiceService(
            InvoiceRepository invoiceRepository,
            InvoiceNumberGenerator invoiceNumberGenerator,
            InvoiceMapper invoiceMapper
    ) {
        this.invoiceRepository = invoiceRepository;
        this.invoiceNumberGenerator = invoiceNumberGenerator;
        this.invoiceMapper = invoiceMapper;
    }

    @Transactional
    public InvoiceResponse generateFromReservation(Long reservationId, CreateInvoiceFromReservationRequest request) {
        if (invoiceRepository.existsByReservationIdAndStatusIn(reservationId, ACTIVE_STATUSES)) {
            throw new IllegalStateException("An active invoice already exists for reservation: " + reservationId);
        }

        ReservationSnapshot reservation = loadReservationSnapshot(reservationId);
        if (!"CHECKED_OUT".equals(reservation.reservationStatus())) {
            throw new IllegalStateException("Reservation must be CHECKED_OUT before invoice generation");
        }

        int nights = calculateNights(reservation.checkInDate(), reservation.checkOutDate());
        BigDecimal subtotalAmount = reservation.pricePerNight()
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
        invoice.setClientFullName(reservation.clientFullName());
        invoice.setRoomId(reservation.roomId());
        invoice.setRoomNumber(reservation.roomNumber());
        invoice.setCheckInDate(reservation.checkInDate());
        invoice.setCheckOutDate(reservation.checkOutDate());
        invoice.setNights(nights);
        invoice.setPricePerNight(reservation.pricePerNight().setScale(2, RoundingMode.HALF_UP));
        invoice.setSubtotalAmount(subtotalAmount);
        invoice.setTaxRate(request.taxRate().setScale(2, RoundingMode.HALF_UP));
        invoice.setTaxAmount(taxAmount);
        invoice.setTotalAmount(totalAmount);
        invoice.setStatus(InvoiceStatus.DRAFT);
        invoice.setNotes(request.notes());

        InvoiceLine roomStayLine = new InvoiceLine();
        roomStayLine.setType(InvoiceLineType.ROOM_STAY);
        roomStayLine.setDescription("Sejour chambre %s - %d nuit(s)".formatted(reservation.roomNumber(), nights));
        roomStayLine.setQuantity(nights);
        roomStayLine.setUnitPrice(reservation.pricePerNight().setScale(2, RoundingMode.HALF_UP));
        roomStayLine.setLineTotal(subtotalAmount);
        invoice.addLine(roomStayLine);

        return invoiceMapper.toResponse(invoiceRepository.save(invoice));
    }

    private int calculateNights(LocalDate checkInDate, LocalDate checkOutDate) {
        long nights = ChronoUnit.DAYS.between(checkInDate, checkOutDate);
        if (nights <= 0) {
            throw new IllegalStateException("Reservation check-out date must be after check-in date");
        }
        return Math.toIntExact(nights);
    }

    private ReservationSnapshot loadReservationSnapshot(Long reservationId) {
        return new ReservationSnapshot(
                reservationId,
                "CHECKED_OUT",
                1L,
                "Temporary Client",
                101L,
                "101",
                LocalDate.now().minusDays(3),
                LocalDate.now(),
                BigDecimal.valueOf(120)
        );
    }

    private record ReservationSnapshot(
            Long reservationId,
            String reservationStatus,
            Long clientId,
            String clientFullName,
            Long roomId,
            String roomNumber,
            LocalDate checkInDate,
            LocalDate checkOutDate,
            BigDecimal pricePerNight
    ) {
    }
}
