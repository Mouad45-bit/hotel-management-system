package com.hotel.management.reservationservice.service;

import com.hotel.management.reservationservice.client.ClientServiceClient;
import com.hotel.management.reservationservice.client.RoomServiceClient;
import com.hotel.management.reservationservice.client.dto.ClientInfo;
import com.hotel.management.reservationservice.client.dto.RoomInfo;
import com.hotel.management.reservationservice.dto.CreateReservationRequest;
import com.hotel.management.reservationservice.dto.ReservationResponse;
import com.hotel.management.reservationservice.dto.UpdateReservationRequest;
import com.hotel.management.reservationservice.entity.Reservation;
import com.hotel.management.reservationservice.entity.ReservationStatus;
import com.hotel.management.reservationservice.exception.BusinessException;
import com.hotel.management.reservationservice.exception.ConflictException;
import com.hotel.management.reservationservice.exception.ResourceNotFoundException;
import com.hotel.management.reservationservice.mapper.ReservationMapper;
import com.hotel.management.reservationservice.repository.ReservationRepository;
import com.hotel.management.reservationservice.repository.ReservationSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class ReservationService {

    private final ReservationRepository reservationRepository;
    private final ReservationMapper reservationMapper;
    private final RoomServiceClient roomServiceClient;
    private final ClientServiceClient clientServiceClient;

    private static final List<ReservationStatus> ACTIVE_STATUSES =
            List.of(ReservationStatus.CREATED, ReservationStatus.CONFIRMED, ReservationStatus.CHECKED_IN);

    private static final Set<String> BLOCKED_ROOM_STATUSES =
            Set.of("MAINTENANCE", "CLEANING", "OUT_OF_SERVICE");

    @Transactional
    public ReservationResponse createReservation(CreateReservationRequest req) {
        validateDates(req.checkInDate(), req.checkOutDate());

        RoomInfo room = roomServiceClient.getRoomById(req.roomId());
        if (!Boolean.TRUE.equals(room.active())) {
            throw new BusinessException("La chambre " + room.number() + " est désactivée et ne peut pas être réservée.");
        }
        if (BLOCKED_ROOM_STATUSES.contains(room.status())) {
            throw new BusinessException("La chambre " + room.number() + " n'est pas disponible (statut : " + room.status() + ").");
        }

        ClientInfo client = clientServiceClient.getClientById(req.clientId());
        if (!Boolean.TRUE.equals(client.active())) {
            throw new BusinessException("Le client " + client.firstName() + " " + client.lastName() + " est désactivé et ne peut pas effectuer de réservation.");
        }

        checkNoOverlap(req.roomId(), req.checkInDate(), req.checkOutDate(), null);

        long nights = ChronoUnit.DAYS.between(req.checkInDate(), req.checkOutDate());
        BigDecimal totalPrice = room.pricePerNight().multiply(BigDecimal.valueOf(nights));

        Reservation reservation = reservationMapper.toEntity(req);
        reservation.setTotalPrice(totalPrice);

        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    public List<ReservationResponse> getReservations(Long roomId, Long clientId, String status, Boolean active) {
        return reservationRepository.findAll(ReservationSpecification.withFilters(roomId, clientId, status, active))
                .stream().map(reservationMapper::toResponse).toList();
    }

    public ReservationResponse getReservationById(Long id) {
        return reservationMapper.toResponse(findActive(id));
    }

    @Transactional
    public ReservationResponse updateReservation(Long id, UpdateReservationRequest req) {
        Reservation reservation = findActive(id);

        if (reservation.getStatus() != ReservationStatus.CREATED) {
            throw new BusinessException("Seules les réservations en statut CREATED peuvent être modifiées.");
        }

        LocalDate newCheckIn = req.checkInDate() != null ? req.checkInDate() : reservation.getCheckInDate();
        LocalDate newCheckOut = req.checkOutDate() != null ? req.checkOutDate() : reservation.getCheckOutDate();
        validateDates(newCheckIn, newCheckOut);

        if (req.checkInDate() != null || req.checkOutDate() != null) {
            checkNoOverlap(reservation.getRoomId(), newCheckIn, newCheckOut, id);

            RoomInfo room = roomServiceClient.getRoomById(reservation.getRoomId());
            long nights = ChronoUnit.DAYS.between(newCheckIn, newCheckOut);
            reservation.setTotalPrice(room.pricePerNight().multiply(BigDecimal.valueOf(nights)));
        }

        reservationMapper.updateEntity(reservation, req);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    @Transactional
    public void deleteReservation(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() == ReservationStatus.CHECKED_IN || reservation.getStatus() == ReservationStatus.CHECKED_OUT) {
            throw new BusinessException("Une réservation en cours ou terminée ne peut pas être supprimée.");
        }
        reservation.setActive(false);
        reservation.setStatus(ReservationStatus.CANCELLED);
        reservationRepository.save(reservation);
    }

    @Transactional
    public ReservationResponse confirmReservation(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() != ReservationStatus.CREATED) {
            throw new BusinessException("Seules les réservations en statut CREATED peuvent être confirmées.");
        }
        reservation.setStatus(ReservationStatus.CONFIRMED);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    @Transactional
    public ReservationResponse checkIn(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() != ReservationStatus.CONFIRMED) {
            throw new BusinessException("Seules les réservations CONFIRMED peuvent passer au check-in.");
        }
        reservation.setStatus(ReservationStatus.CHECKED_IN);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    @Transactional
    public ReservationResponse checkOut(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() != ReservationStatus.CHECKED_IN) {
            throw new BusinessException("Seules les réservations CHECKED_IN peuvent passer au check-out.");
        }
        reservation.setStatus(ReservationStatus.CHECKED_OUT);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    @Transactional
    public ReservationResponse cancelReservation(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() == ReservationStatus.CHECKED_IN
                || reservation.getStatus() == ReservationStatus.CHECKED_OUT
                || reservation.getStatus() == ReservationStatus.NO_SHOW) {
            throw new BusinessException("Une réservation en cours, terminée ou no-show ne peut pas être annulée.");
        }
        reservation.setStatus(ReservationStatus.CANCELLED);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    @Transactional
    public ReservationResponse noShow(Long id) {
        Reservation reservation = findActive(id);
        if (reservation.getStatus() != ReservationStatus.CONFIRMED) {
            throw new BusinessException("Seules les réservations CONFIRMED peuvent être marquées comme no-show.");
        }
        reservation.setStatus(ReservationStatus.NO_SHOW);
        return reservationMapper.toResponse(reservationRepository.save(reservation));
    }

    public List<ReservationResponse> getReservationsByClient(Long clientId) {
        return reservationRepository.findByClientIdAndActiveTrue(clientId)
                .stream().map(reservationMapper::toResponse).toList();
    }

    public List<ReservationResponse> getReservationsByRoom(Long roomId) {
        return reservationRepository.findByRoomIdAndActiveTrue(roomId)
                .stream().map(reservationMapper::toResponse).toList();
    }

    public List<ReservationResponse> getAvailability(Long roomId, LocalDate from, LocalDate to) {
        if (from != null && to != null) {
            validateDates(from, to);
        }
        return reservationRepository.findOverlappingReservations(
                        roomId, from, to, ACTIVE_STATUSES)
                .stream().map(reservationMapper::toResponse).toList();
    }

    public List<ReservationResponse> getTodayCheckIns() {
        LocalDate today = LocalDate.now();
        return reservationRepository.findByCheckInDateAndStatusIn(today, List.of(ReservationStatus.CONFIRMED))
                .stream().map(reservationMapper::toResponse).toList();
    }

    public List<ReservationResponse> getTodayCheckOuts() {
        LocalDate today = LocalDate.now();
        return reservationRepository.findByCheckOutDateAndStatusIn(today, List.of(ReservationStatus.CHECKED_IN))
                .stream().map(reservationMapper::toResponse).toList();
    }

    private Reservation findActive(Long id) {
        return reservationRepository.findById(id)
                .filter(r -> Boolean.TRUE.equals(r.getActive()))
                .orElseThrow(() -> new ResourceNotFoundException("Réservation introuvable avec l'identifiant : " + id));
    }

    private void validateDates(LocalDate checkIn, LocalDate checkOut) {
        if (!checkOut.isAfter(checkIn)) {
            throw new BusinessException("La date de départ doit être strictement après la date d'arrivée.");
        }
    }

    private void checkNoOverlap(Long roomId, LocalDate checkIn, LocalDate checkOut, Long excludeId) {
        boolean overlap = excludeId == null
                ? reservationRepository.existsOverlappingReservation(roomId, checkIn, checkOut, ACTIVE_STATUSES)
                : reservationRepository.existsOverlappingReservationExcluding(roomId, checkIn, checkOut, ACTIVE_STATUSES, excludeId);

        if (overlap) {
            throw new ConflictException("La chambre est déjà réservée pour cette période.");
        }
    }
}
