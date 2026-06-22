package com.hotel.management.reservationservice.mapper;

import com.hotel.management.reservationservice.dto.CreateReservationRequest;
import com.hotel.management.reservationservice.dto.ReservationResponse;
import com.hotel.management.reservationservice.dto.UpdateReservationRequest;
import com.hotel.management.reservationservice.entity.Reservation;
import org.springframework.stereotype.Component;

@Component
public class ReservationMapper {

    public Reservation toEntity(CreateReservationRequest req) {
        return Reservation.builder()
                .roomId(req.roomId())
                .clientId(req.clientId())
                .checkInDate(req.checkInDate())
                .checkOutDate(req.checkOutDate())
                .notes(req.notes())
                .build();
    }

    public void updateEntity(Reservation reservation, UpdateReservationRequest req) {
        if (req.checkInDate() != null) reservation.setCheckInDate(req.checkInDate());
        if (req.checkOutDate() != null) reservation.setCheckOutDate(req.checkOutDate());
        if (req.notes() != null) reservation.setNotes(req.notes());
    }

    public ReservationResponse toResponse(Reservation reservation) {
        return new ReservationResponse(
                reservation.getId(),
                reservation.getRoomId(),
                reservation.getClientId(),
                reservation.getCheckInDate(),
                reservation.getCheckOutDate(),
                reservation.getStatus(),
                reservation.getTotalPrice(),
                reservation.getNotes(),
                reservation.getActive(),
                reservation.getCreatedAt(),
                reservation.getUpdatedAt()
        );
    }
}
