package com.hotel.management.invoiceservice.service;

import com.hotel.management.invoiceservice.dto.CreateInvoiceFromReservationRequest;
import com.hotel.management.invoiceservice.dto.InvoiceResponse;
import com.hotel.management.invoiceservice.dto.external.ClientSummaryResponse;
import com.hotel.management.invoiceservice.dto.external.ReservationSummaryResponse;
import com.hotel.management.invoiceservice.dto.external.RoomSummaryResponse;
import com.hotel.management.invoiceservice.entity.Invoice;
import com.hotel.management.invoiceservice.entity.InvoiceLine;
import com.hotel.management.invoiceservice.entity.InvoiceLineType;
import com.hotel.management.invoiceservice.entity.InvoiceStatus;
import com.hotel.management.invoiceservice.mapper.InvoiceMapper;
import com.hotel.management.invoiceservice.repository.InvoiceRepository;
import com.hotel.management.invoiceservice.service.client.ClientClient;
import com.hotel.management.invoiceservice.service.client.ReservationClient;
import com.hotel.management.invoiceservice.service.client.RoomClient;
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

    @Transactional
    public InvoiceResponse generateFromReservation(Long reservationId, CreateInvoiceFromReservationRequest request) {
        if (invoiceRepository.existsByReservationIdAndStatusIn(reservationId, ACTIVE_STATUSES)) {
            throw new IllegalStateException("An active invoice already exists for reservation: " + reservationId);
        }

        ReservationSummaryResponse reservation = reservationClient.findSummaryById(reservationId);
        ClientSummaryResponse client = clientClient.findSummaryById(reservation.clientId());
        RoomSummaryResponse room = roomClient.findSummaryById(reservation.roomId());

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
        invoice.setClientFullName(client.fullName());
        invoice.setRoomId(reservation.roomId());
        invoice.setRoomNumber(room.roomNumber());
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
        roomStayLine.setDescription("Sejour chambre %s - %d nuit(s)".formatted(room.roomNumber(), nights));
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
}
