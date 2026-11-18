package com.hotel.management.reservationservice.controller;

import com.hotel.management.reservationservice.dto.PublicBookingRequest;
import com.hotel.management.reservationservice.dto.PublicBookingResponse;
import com.hotel.management.reservationservice.dto.PublicRoomResponse;
import com.hotel.management.reservationservice.service.PublicBookingService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicBookingController {

    private final PublicBookingService publicBookingService;

    @GetMapping("/rooms/available")
    public ResponseEntity<List<PublicRoomResponse>> getAvailableRooms(
            @RequestParam LocalDate checkIn,
            @RequestParam LocalDate checkOut,
            @RequestParam(required = false) String type) {
        return ResponseEntity.ok(publicBookingService.getAvailableRooms(checkIn, checkOut, type));
    }

    @GetMapping("/rooms/{id}")
    public ResponseEntity<PublicRoomResponse> getRoomById(@PathVariable Long id) {
        return ResponseEntity.ok(publicBookingService.getRoomById(id));
    }

    @PostMapping("/book")
    public ResponseEntity<PublicBookingResponse> createBooking(@Valid @RequestBody PublicBookingRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(publicBookingService.createBooking(request));
    }

    @GetMapping("/booking/{reference}")
    public ResponseEntity<PublicBookingResponse> getBooking(
            @PathVariable String reference,
            @RequestParam String email) {
        return ResponseEntity.ok(publicBookingService.getBookingByReference(reference, email));
    }
}
