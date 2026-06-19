package com.hotel.management.housekeepingservice.dto.external;

public record RoomSummaryResponse(
        Long roomId,
        String roomNumber,
        String status,
        boolean active
) {
}
