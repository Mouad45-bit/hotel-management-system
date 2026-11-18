package com.hotel.management.roomservice.dto;

public record RoomStatsResponse(
    long total,
    long available,
    long occupied,
    long reserved,
    long cleaning,
    long maintenance,
    long outOfService
) {
}