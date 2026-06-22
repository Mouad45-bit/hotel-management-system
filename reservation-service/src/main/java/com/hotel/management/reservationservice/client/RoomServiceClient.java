package com.hotel.management.reservationservice.client;

import com.hotel.management.reservationservice.client.dto.RoomInfo;
import com.hotel.management.reservationservice.exception.ResourceNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Component
public class RoomServiceClient {

    private final RestClient restClient;

    public RoomServiceClient(RestClient gatewayRestClient) {
        this.restClient = gatewayRestClient;
    }

    public RoomInfo getRoomById(Long roomId) {
        try {
            return restClient.get()
                    .uri("/api/rooms/{id}", roomId)
                    .retrieve()
                    .body(RoomInfo.class);
        } catch (HttpClientErrorException.NotFound e) {
            throw new ResourceNotFoundException("Chambre introuvable avec l'identifiant : " + roomId);
        } catch (Exception e) {
            throw new RuntimeException("Impossible de contacter le service des chambres : " + e.getMessage());
        }
    }
}
