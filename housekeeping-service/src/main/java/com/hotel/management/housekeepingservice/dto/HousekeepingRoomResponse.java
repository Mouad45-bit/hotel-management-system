package com.hotel.management.housekeepingservice.dto;

public record HousekeepingRoomResponse(
        Long id,
        String roomNumber,
        String status,
        boolean active
) {
}
