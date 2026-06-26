package com.hotel.management.reservationservice.repository;

import com.hotel.management.reservationservice.entity.Reservation;
import com.hotel.management.reservationservice.entity.ReservationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface ReservationRepository extends JpaRepository<Reservation, Long>, JpaSpecificationExecutor<Reservation> {

    Optional<Reservation> findByReferenceAndActiveTrue(String reference);

    List<Reservation> findByClientIdAndActiveTrue(Long clientId);

    List<Reservation> findByRoomIdAndActiveTrue(Long roomId);

    List<Reservation> findByCheckInDateAndStatusIn(LocalDate checkInDate, List<ReservationStatus> statuses);

    List<Reservation> findByCheckOutDateAndStatusIn(LocalDate checkOutDate, List<ReservationStatus> statuses);

    @Query("""
            SELECT COUNT(r) > 0 FROM Reservation r
            WHERE r.roomId = :roomId
              AND r.status IN :statuses
              AND r.checkInDate < :checkOutDate
              AND r.checkOutDate > :checkInDate
            """)
    boolean existsOverlappingReservation(
            @Param("roomId") Long roomId,
            @Param("checkInDate") LocalDate checkInDate,
            @Param("checkOutDate") LocalDate checkOutDate,
            @Param("statuses") List<ReservationStatus> statuses
    );

    @Query("""
            SELECT COUNT(r) > 0 FROM Reservation r
            WHERE r.roomId = :roomId
              AND r.id <> :excludeId
              AND r.status IN :statuses
              AND r.checkInDate < :checkOutDate
              AND r.checkOutDate > :checkInDate
            """)
    boolean existsOverlappingReservationExcluding(
            @Param("roomId") Long roomId,
            @Param("checkInDate") LocalDate checkInDate,
            @Param("checkOutDate") LocalDate checkOutDate,
            @Param("statuses") List<ReservationStatus> statuses,
            @Param("excludeId") Long excludeId
    );

    @Query("""
            SELECT r FROM Reservation r
            WHERE r.status IN :statuses
              AND (:roomId IS NULL OR r.roomId = :roomId)
              AND (:from IS NULL OR r.checkOutDate > :from)
              AND (:to IS NULL OR r.checkInDate < :to)
            ORDER BY r.checkInDate
            """)
    List<Reservation> findOverlappingReservations(
            @Param("roomId") Long roomId,
            @Param("from") LocalDate from,
            @Param("to") LocalDate to,
            @Param("statuses") List<ReservationStatus> statuses
    );
}
