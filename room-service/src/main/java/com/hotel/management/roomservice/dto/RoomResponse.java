package com.hotel.management.roomservice.dto;

import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public record RoomResponse(
    Long id,
    String number,
    Integer floor,
    RoomType type,
    BigDecimal pricePerNight,
    Integer capacity,
    RoomStatus status,
    String description,
    Boolean active,
    LocalDateTime createdAt,
    LocalDateTime updatedAt
) {
}
