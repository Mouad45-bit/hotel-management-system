package com.hotel.management.staffservice.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record LinkAuthUserRequest(
        @NotNull(message = "User id is required")
        @Positive(message = "User id must be positive")
        Long userId
) {
}
