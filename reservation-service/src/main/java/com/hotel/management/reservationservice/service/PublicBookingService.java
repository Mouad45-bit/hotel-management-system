package com.hotel.management.reservationservice.service;

import com.hotel.management.reservationservice.client.ClientServiceClient;
import com.hotel.management.reservationservice.client.RoomServiceClient;
import com.hotel.management.reservationservice.client.dto.ClientCreateRequest;
import com.hotel.management.reservationservice.client.dto.FullClientInfo;
import com.hotel.management.reservationservice.client.dto.FullRoomInfo;
import com.hotel.management.reservationservice.dto.PublicBookingRequest;
import com.hotel.management.reservationservice.dto.PublicBookingResponse;
import com.hotel.management.reservationservice.dto.PublicRoomResponse;
import com.hotel.management.reservationservice.entity.Reservation;
import com.hotel.management.reservationservice.entity.ReservationStatus;
import com.hotel.management.reservationservice.exception.BusinessException;
import com.hotel.management.reservationservice.exception.ConflictException;
import com.hotel.management.reservationservice.exception.ResourceNotFoundException;
import com.hotel.management.reservationservice.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PublicBookingService {

    private final ReservationRepository reservationRepository;
    private final RoomServiceClient roomServiceClient;
    private final ClientServiceClient clientServiceClient;

    private static final List<ReservationStatus> ACTIVE_STATUSES =
            List.of(ReservationStatus.CREATED, ReservationStatus.CONFIRMED, ReservationStatus.CHECKED_IN);

    private static final Set<String> BLOCKED_ROOM_STATUSES =
            Set.of("MAINTENANCE", "CLEANING", "OUT_OF_SERVICE");

    public PublicRoomResponse getRoomById(Long id) {
        FullRoomInfo room = roomServiceClient.getFullRoomById(id);
        return new PublicRoomResponse(
                room.id(), room.number(), room.type(), room.floor(),
                room.pricePerNight(), room.capacity(), room.description());
    }

    public List<PublicRoomResponse> getAvailableRooms(LocalDate checkIn, LocalDate checkOut, String type) {
        if (checkIn == null || checkOut == null) {
            throw new BusinessException("Les dates d'arrivée et de départ sont obligatoires.");
        }
        if (!checkOut.isAfter(checkIn)) {
            throw new BusinessException("La date de départ doit être après la date d'arrivée.");
        }
        if (checkIn.isBefore(LocalDate.now())) {
            throw new BusinessException("La date d'arrivée ne peut pas être dans le passé.");
        }

        List<FullRoomInfo> allRooms = roomServiceClient.getAvailableRooms(type);

        return allRooms.stream()
                .filter(room -> !reservationRepository.existsOverlappingReservation(
                        room.id(), checkIn, checkOut, ACTIVE_STATUSES))
                .map(room -> new PublicRoomResponse(
                        room.id(), room.number(), room.type(), room.floor(),
                        room.pricePerNight(), room.capacity(), room.description()))
                .toList();
    }

    @Transactional
    public PublicBookingResponse createBooking(PublicBookingRequest req) {
        if (!req.checkOutDate().isAfter(req.checkInDate())) {
            throw new BusinessException("La date de départ doit être après la date d'arrivée.");
        }

        FullRoomInfo room = roomServiceClient.getFullRoomById(req.roomId());
        if (!Boolean.TRUE.equals(room.active())) {
            throw new BusinessException("Cette chambre n'est pas disponible.");
        }
        if (BLOCKED_ROOM_STATUSES.contains(room.status())) {
            throw new BusinessException("Cette chambre n'est pas disponible (statut : " + room.status() + ").");
        }

        if (reservationRepository.existsOverlappingReservation(
                req.roomId(), req.checkInDate(), req.checkOutDate(), ACTIVE_STATUSES)) {
            throw new ConflictException("Cette chambre est déjà réservée pour cette période.");
        }

        Long clientId = findOrCreateClient(req);

        long nights = ChronoUnit.DAYS.between(req.checkInDate(), req.checkOutDate());
        BigDecimal totalPrice = room.pricePerNight().multiply(BigDecimal.valueOf(nights));

        String reference = generateReference();

        Reservation reservation = Reservation.builder()
                .roomId(req.roomId())
                .clientId(clientId)
                .checkInDate(req.checkInDate())
                .checkOutDate(req.checkOutDate())
                .totalPrice(totalPrice)
                .notes(req.specialRequests())
                .reference(reference)
                .status(ReservationStatus.CONFIRMED)
                .build();

        Reservation saved = reservationRepository.save(reservation);
        roomServiceClient.updateRoomStatus(req.roomId(), "RESERVED");

        return new PublicBookingResponse(
                saved.getReference(),
                req.firstName() + " " + req.lastName(),
                req.email(),
                room.number(),
                room.type(),
                saved.getCheckInDate(),
                saved.getCheckOutDate(),
                nights,
                totalPrice,
                saved.getStatus().name(),
                saved.getNotes(),
                saved.getCreatedAt()
        );
    }

    public PublicBookingResponse getBookingByReference(String reference, String email) {
        Reservation reservation = reservationRepository.findByReferenceAndActiveTrue(reference)
                .orElseThrow(() -> new ResourceNotFoundException("Réservation introuvable avec la référence : " + reference));

        FullClientInfo client = clientServiceClient.findByEmail(email);
        if (client == null || !client.id().equals(reservation.getClientId())) {
            throw new BusinessException("L'email ne correspond pas à cette réservation.");
        }

        FullRoomInfo room = roomServiceClient.getFullRoomById(reservation.getRoomId());
        long nights = ChronoUnit.DAYS.between(reservation.getCheckInDate(), reservation.getCheckOutDate());

        return new PublicBookingResponse(
                reservation.getReference(),
                client.firstName() + " " + client.lastName(),
                client.email(),
                room.number(),
                room.type(),
                reservation.getCheckInDate(),
                reservation.getCheckOutDate(),
                nights,
                reservation.getTotalPrice(),
                reservation.getStatus().name(),
                reservation.getNotes(),
                reservation.getCreatedAt()
        );
    }

    private Long findOrCreateClient(PublicBookingRequest req) {
        FullClientInfo existing = clientServiceClient.findByEmail(req.email());
        if (existing != null) {
            return existing.id();
        }

        FullClientInfo created = clientServiceClient.createClient(
                new ClientCreateRequest(req.firstName(), req.lastName(), req.email(), req.phone()));
        return created.id();
    }

    private String generateReference() {
        String ref = "HMS-" + LocalDate.now().getYear() + "-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        while (reservationRepository.findByReferenceAndActiveTrue(ref).isPresent()) {
            ref = "HMS-" + LocalDate.now().getYear() + "-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        }
        return ref;
    }
}
