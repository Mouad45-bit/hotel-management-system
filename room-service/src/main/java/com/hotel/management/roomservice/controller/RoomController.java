package com.hotel.management.roomservice.controller;

import com.hotel.management.roomservice.dto.RoomRequest;
import com.hotel.management.roomservice.dto.RoomResponse;
import com.hotel.management.roomservice.dto.RoomStatsResponse;
import com.hotel.management.roomservice.dto.UpdateRoomStatusRequest;
import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;
import com.hotel.management.roomservice.service.RoomService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/rooms")
@RequiredArgsConstructor
public class RoomController {

    private final RoomService roomService;

    @PostMapping
    public ResponseEntity<RoomResponse> createRoom(@Valid @RequestBody RoomRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roomService.createRoom(request));
    }

    @GetMapping
    public ResponseEntity<List<RoomResponse>> getAllRooms(
            @RequestParam(required = false) String number,
            @RequestParam(required = false) RoomType type,
            @RequestParam(required = false) RoomStatus status,
            @RequestParam(required = false) Integer floor,
            @RequestParam(required = false) Integer capacity,
            @RequestParam(required = false) Boolean active) {
        return ResponseEntity.ok(roomService.getAllRooms(number, type, status, floor, capacity, active));
    }

    @GetMapping("/stats")
    public ResponseEntity<RoomStatsResponse> getRoomStats() {
        return ResponseEntity.ok(roomService.getRoomStats());
    }

    @GetMapping("/{id}")
    public ResponseEntity<RoomResponse> getRoomById(@PathVariable Long id) {
        return ResponseEntity.ok(roomService.getRoomById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<RoomResponse> updateRoom(
        @PathVariable Long id,
        @Valid @RequestBody RoomRequest request) {
        return ResponseEntity.ok(roomService.updateRoom(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRoom(@PathVariable Long id) {
        roomService.deleteRoom(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<RoomResponse> updateRoomStatus(
        @PathVariable Long id,
        @Valid @RequestBody UpdateRoomStatusRequest request) {
        return ResponseEntity.ok(roomService.updateRoomStatus(id, request.status()));
    }

    @GetMapping("/disabled")
    public ResponseEntity<List<RoomResponse>> getDisabledRooms() {
        return ResponseEntity.ok(roomService.getDisabledRooms());
    }

    @PatchMapping("/{id}/activate")
    public ResponseEntity<Void> activateRoom(@PathVariable Long id) {
        roomService.activateRoom(id);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/{id}/deactivate")
    public ResponseEntity<Void> deactivateRoom(@PathVariable Long id) {
        roomService.deactivateRoom(id);
        return ResponseEntity.ok().build();
    }
}
