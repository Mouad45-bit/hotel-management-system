package com.hotel.management.clientservice.dto;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record ClientResponse(
    Long id,
    String firstName,
    String lastName,
    String email,
    String phone,
    String cin,
    String passportNumber,
    String nationality,
    String address,
    LocalDate birthDate,
    Boolean active,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {}
