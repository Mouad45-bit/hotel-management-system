package com.hotel.management.housekeepingservice.dto;

public record HousekeepingAgentResponse(
        Long id,
        String fullName,
        String department,
        boolean active
) {
}
