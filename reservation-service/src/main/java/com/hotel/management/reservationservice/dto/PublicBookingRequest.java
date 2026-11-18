package com.hotel.management.reservationservice.dto;

import jakarta.validation.constraints.*;

import java.time.LocalDate;

public record PublicBookingRequest(

        @NotBlank(message = "Le prénom est obligatoire")
        String firstName,

        @NotBlank(message = "Le nom est obligatoire")
        String lastName,

        @NotBlank(message = "L'email est obligatoire")
        @Email(message = "L'email doit être valide")
        String email,

        String phone,

        @NotNull(message = "L'identifiant de la chambre est obligatoire")
        Long roomId,

        @NotNull(message = "La date d'arrivée est obligatoire")
        @FutureOrPresent(message = "La date d'arrivée doit être aujourd'hui ou dans le futur")
        LocalDate checkInDate,

        @NotNull(message = "La date de départ est obligatoire")
        @Future(message = "La date de départ doit être dans le futur")
        LocalDate checkOutDate,

        String specialRequests
) {}
