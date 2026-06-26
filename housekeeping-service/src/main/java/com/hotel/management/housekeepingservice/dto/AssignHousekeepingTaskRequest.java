package com.hotel.management.housekeepingservice.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record AssignHousekeepingTaskRequest(
        @NotNull(message = "Assigned agent id is required")
        @Positive(message = "Assigned agent id must be positive")
        Long assignedAgentId
) {
}
