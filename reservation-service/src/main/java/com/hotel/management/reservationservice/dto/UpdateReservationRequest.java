package com.hotel.management.reservationservice.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.FutureOrPresent;

import java.time.LocalDate;

public record UpdateReservationRequest(

        @FutureOrPresent(message = "La date d'arrivée doit être aujourd'hui ou dans le futur")
        LocalDate checkInDate,

        @Future(message = "La date de départ doit être dans le futur")
        LocalDate checkOutDate,

        String notes
) {}
