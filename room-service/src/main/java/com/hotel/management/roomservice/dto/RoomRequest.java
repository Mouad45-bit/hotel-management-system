package com.hotel.management.roomservice.dto;

import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;

import java.math.BigDecimal;

public record RoomRequest(
    @NotBlank(message = "Room number is required")
    String number,

    @NotNull(message = "Floor is required")
    @Min(value = 0, message = "Floor must be 0 or positive")
    Integer floor,

    @NotNull(message = "Room type is required")
    RoomType type,

    @NotNull(message = "Price per night is required")
    @PositiveOrZero(message = "Price per night must be zero or positive")
    BigDecimal pricePerNight,

    @NotNull(message = "Capacity is required")
    @Positive(message = "Capacity must be positive")
    Integer capacity,

    @NotNull(message = "Room status is required")
    RoomStatus status,

    String description
) {
}
