package com.hotel.management.housekeepingservice.dto.external;

import com.fasterxml.jackson.annotation.JsonAlias;

public record RoomSummaryResponse(
        @JsonAlias("id")
        Long roomId,
        @JsonAlias("number")
        String roomNumber,
        String status,
        boolean active
) {
}
