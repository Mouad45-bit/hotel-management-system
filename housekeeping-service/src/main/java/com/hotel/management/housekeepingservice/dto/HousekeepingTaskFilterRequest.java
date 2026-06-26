package com.hotel.management.housekeepingservice.dto;

import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;

import java.time.LocalDate;

public record HousekeepingTaskFilterRequest(
        HousekeepingTaskStatus status,
        HousekeepingTaskType type,
        Priority priority,
        Long roomId,
        Long agentId,
        LocalDate scheduledDate,
        LocalDate from,
        LocalDate to,
        Integer page,
        Integer size,
        String sort
) {
}
