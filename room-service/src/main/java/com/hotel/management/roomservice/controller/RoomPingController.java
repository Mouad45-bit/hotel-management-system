package com.hotel.management.roomservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

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
    public Map<String, String> ping() {
        return Map.of(
                "service", "room-service",
                "status", "UP"
        );
    }
}
