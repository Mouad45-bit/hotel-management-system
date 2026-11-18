package com.hotel.management.housekeepingservice.dto.external;

import com.fasterxml.jackson.annotation.JsonAlias;

public record StaffSummaryResponse(
        @JsonAlias("id")
        Long employeeId,
        @JsonAlias({"name", "fullName"})
        String fullName,
        String department,
        boolean active
) {
}
