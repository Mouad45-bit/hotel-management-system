package com.hotel.management.housekeepingservice.dto;

import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record CreateHousekeepingTaskRequest(
        @NotNull(message = "Room id is required")
        @Positive(message = "Room id must be positive")
        Long roomId,

        @Positive(message = "Reservation id must be positive")
        Long reservationId,

        @NotNull(message = "Task type is required")
        HousekeepingTaskType type,

        @NotNull(message = "Priority is required")
        Priority priority,

        @NotNull(message = "Scheduled date is required")
        @FutureOrPresent(message = "Scheduled date must be today or in the future")
        LocalDate scheduledDate,

        @Positive(message = "Assigned agent id must be positive")
        Long assignedAgentId,

        @Size(max = 500, message = "Notes must not exceed 500 characters")
        String notes
) {
}
