package com.hotel.management.reservationservice.controller;

import com.hotel.management.reservationservice.dto.CreateReservationRequest;
import com.hotel.management.reservationservice.dto.ReservationResponse;
import com.hotel.management.reservationservice.dto.UpdateReservationRequest;
import com.hotel.management.reservationservice.service.ReservationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/api/reservations")
@RequiredArgsConstructor
public class ReservationController {

    private final ReservationService reservationService;

    @PostMapping
    public ResponseEntity<ReservationResponse> createReservation(@Valid @RequestBody CreateReservationRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(reservationService.createReservation(req));
    }

    @GetMapping
    public ResponseEntity<List<ReservationResponse>> getReservations(
            @RequestParam(required = false) Long roomId,
            @RequestParam(required = false) Long clientId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Boolean active
    ) {
        return ResponseEntity.ok(reservationService.getReservations(roomId, clientId, status, active));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ReservationResponse> getReservationById(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.getReservationById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ReservationResponse> updateReservation(
            @PathVariable Long id,
            @Valid @RequestBody UpdateReservationRequest req
    ) {
        return ResponseEntity.ok(reservationService.updateReservation(id, req));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteReservation(@PathVariable Long id) {
        reservationService.deleteReservation(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/confirm")
    public ResponseEntity<ReservationResponse> confirmReservation(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.confirmReservation(id));
    }

    @PatchMapping("/{id}/check-in")
    public ResponseEntity<ReservationResponse> checkIn(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.checkIn(id));
    }

    @PatchMapping("/{id}/check-out")
    public ResponseEntity<ReservationResponse> checkOut(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.checkOut(id));
    }

    @PatchMapping("/{id}/cancel")
    public ResponseEntity<ReservationResponse> cancelReservation(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.cancelReservation(id));
    }

    @PatchMapping("/{id}/no-show")
    public ResponseEntity<ReservationResponse> noShow(@PathVariable Long id) {
        return ResponseEntity.ok(reservationService.noShow(id));
    }

    @GetMapping("/client/{clientId}")
    public ResponseEntity<List<ReservationResponse>> getReservationsByClient(@PathVariable Long clientId) {
        return ResponseEntity.ok(reservationService.getReservationsByClient(clientId));
    }

    @GetMapping("/room/{roomId}")
    public ResponseEntity<List<ReservationResponse>> getReservationsByRoom(@PathVariable Long roomId) {
        return ResponseEntity.ok(reservationService.getReservationsByRoom(roomId));
    }

    @GetMapping("/availability")
    public ResponseEntity<List<ReservationResponse>> getAvailability(
            @RequestParam(required = false) Long roomId,
            @RequestParam(required = false) LocalDate from,
            @RequestParam(required = false) LocalDate to
    ) {
        return ResponseEntity.ok(reservationService.getAvailability(roomId, from, to));
    }

    @GetMapping("/today/check-ins")
    public ResponseEntity<List<ReservationResponse>> getTodayCheckIns() {
        return ResponseEntity.ok(reservationService.getTodayCheckIns());
    }

    @GetMapping("/today/check-outs")
    public ResponseEntity<List<ReservationResponse>> getTodayCheckOuts() {
        return ResponseEntity.ok(reservationService.getTodayCheckOuts());
    }
}
