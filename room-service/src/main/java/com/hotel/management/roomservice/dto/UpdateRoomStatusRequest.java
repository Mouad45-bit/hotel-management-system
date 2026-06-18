package com.hotel.management.roomservice.dto;

import com.hotel.management.roomservice.entity.RoomStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateRoomStatusRequest(
    @NotNull(message = "Room status is required")
    RoomStatus status
) {
}
