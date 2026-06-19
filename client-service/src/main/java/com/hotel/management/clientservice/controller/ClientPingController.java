package com.hotel.management.clientservice.controller;

import com.hotel.management.clientservice.dto.PingResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clients")
public class ClientPingController {

    @GetMapping("/ping")
    public ResponseEntity<PingResponse> ping() {
        return ResponseEntity.ok(new PingResponse("client-service", "UP", "Client service is running"));
    }
}
