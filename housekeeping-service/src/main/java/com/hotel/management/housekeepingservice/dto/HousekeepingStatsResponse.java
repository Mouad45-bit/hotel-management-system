package com.hotel.management.housekeepingservice.dto;

public record HousekeepingStatsResponse(
        long total,
        long todo,
        long inProgress,
        long done,
        long cancelled,
        long urgent,
        long unassigned
) {
}
