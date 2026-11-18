package com.hotel.management.clientservice.controller;

import com.hotel.management.clientservice.dto.ClientResponse;
import com.hotel.management.clientservice.dto.CreateClientRequest;
import com.hotel.management.clientservice.dto.UpdateClientRequest;
import com.hotel.management.clientservice.dto.external.ClientReservationResponse;
import com.hotel.management.clientservice.service.ClientService;
import com.hotel.management.clientservice.service.client.ReservationServiceClient;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final ClientService clientService;
    private final ReservationServiceClient reservationServiceClient;

    @PostMapping
    public ResponseEntity<ClientResponse> createClient(@Valid @RequestBody CreateClientRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.createClient(request));
    }

    @GetMapping
    public ResponseEntity<List<ClientResponse>> getAllClients(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) Boolean active) {
        return ResponseEntity.ok(clientService.getAllClients(search, active));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ClientResponse> getClientById(@PathVariable Long id) {
        return ResponseEntity.ok(clientService.getClientById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ClientResponse> updateClient(
            @PathVariable Long id,
            @Valid @RequestBody UpdateClientRequest request) {
        return ResponseEntity.ok(clientService.updateClient(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable Long id) {
        clientService.deleteClient(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/activate")
    public ResponseEntity<Void> activateClient(@PathVariable Long id) {
        clientService.activateClient(id);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/{id}/deactivate")
    public ResponseEntity<Void> deactivateClient(@PathVariable Long id) {
        clientService.deactivateClient(id);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/search")
    public ResponseEntity<List<ClientResponse>> searchClients(@RequestParam(required = false) String q) {
        return ResponseEntity.ok(clientService.searchClients(q));
    }

    @GetMapping("/by-email")
    public ResponseEntity<ClientResponse> getClientByEmail(@RequestParam String email) {
        return ResponseEntity.ok(clientService.getClientByEmail(email));
    }

    @GetMapping("/{id}/reservations")
    public ResponseEntity<List<ClientReservationResponse>> getClientReservations(@PathVariable Long id) {
        clientService.getClientById(id);
        return ResponseEntity.ok(reservationServiceClient.getReservationsByClientId(id));
    }
}
