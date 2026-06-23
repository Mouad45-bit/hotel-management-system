package com.hotel.management.housekeepingservice.dto;

import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record UpdateHousekeepingTaskRequest(
        HousekeepingTaskType type,

        Priority priority,

        LocalDate scheduledDate,

        @Size(max = 500, message = "Notes must not exceed 500 characters")
        String notes
) {
}
