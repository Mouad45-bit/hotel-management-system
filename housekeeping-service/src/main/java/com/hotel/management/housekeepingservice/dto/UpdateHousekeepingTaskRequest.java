package com.hotel.management.housekeepingservice.dto;

import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record UpdateHousekeepingTaskRequest(
        @NotNull(message = "Task type is required")
        HousekeepingTaskType type,

        @NotNull(message = "Priority is required")
        Priority priority,

        @NotNull(message = "Scheduled date is required")
        LocalDate scheduledDate,

        @Size(max = 500, message = "Notes must not exceed 500 characters")
        String notes
) {
}
