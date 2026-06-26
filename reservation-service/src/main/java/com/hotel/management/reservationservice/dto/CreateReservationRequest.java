package com.hotel.management.reservationservice.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record CreateReservationRequest(

        @NotNull(message = "L'identifiant de la chambre est obligatoire")
        Long roomId,

        @NotNull(message = "L'identifiant du client est obligatoire")
        Long clientId,

        @NotNull(message = "La date d'arrivée est obligatoire")
        @FutureOrPresent(message = "La date d'arrivée doit être aujourd'hui ou dans le futur")
        LocalDate checkInDate,

        @NotNull(message = "La date de départ est obligatoire")
        @Future(message = "La date de départ doit être dans le futur")
        LocalDate checkOutDate,

        String notes
) {}
