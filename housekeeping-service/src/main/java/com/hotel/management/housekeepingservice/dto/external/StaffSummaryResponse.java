package com.hotel.management.housekeepingservice.dto.external;

public record StaffSummaryResponse(
        Long employeeId,
        String fullName,
        String department,
        boolean active
) {
}
