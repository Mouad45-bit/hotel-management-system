package com.hotel.management.housekeepingservice.dto;

import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record HousekeepingTaskResponse(
        Long id,
        Long roomId,
        String roomNumber,
        Long reservationId,
        Long assignedAgentId,
        String assignedAgentName,
        HousekeepingTaskType type,
        HousekeepingTaskStatus status,
        Priority priority,
        LocalDate scheduledDate,
        LocalDateTime startedAt,
        LocalDateTime completedAt,
        LocalDateTime cancelledAt,
        String cancellationReason,
        String notes,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
