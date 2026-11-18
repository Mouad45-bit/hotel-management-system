package com.hotel.management.roomservice.controller;

import com.hotel.management.roomservice.dto.PingResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Temporary technical endpoint used to validate:
 * - room-service startup
 * - Gateway route /api/rooms/**
 * - Docker Compose integration
 *
 * Business endpoints will be implemented in the next sprint.
 */
@RestController
public class RoomPingController {

    @GetMapping("/api/rooms/ping")
    public PingResponse ping() {
        return new PingResponse(
            "room-service",
            "UP"
        );
    }
}
