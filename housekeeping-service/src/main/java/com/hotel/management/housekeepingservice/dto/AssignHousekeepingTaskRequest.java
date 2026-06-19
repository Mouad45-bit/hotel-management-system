package com.hotel.management.housekeepingservice.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record AssignHousekeepingTaskRequest(
        @NotNull(message = "Agent id is required")
        @Positive(message = "Agent id must be positive")
        Long agentId,

        @Size(max = 160, message = "Agent name must not exceed 160 characters")
        String agentName
) {
}
