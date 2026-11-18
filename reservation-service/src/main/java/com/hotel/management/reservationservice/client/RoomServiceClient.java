package com.hotel.management.reservationservice.client;

import com.hotel.management.reservationservice.client.dto.FullRoomInfo;
import com.hotel.management.reservationservice.client.dto.RoomInfo;
import com.hotel.management.reservationservice.exception.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Component
public class RoomServiceClient {

    private static final Logger log = LoggerFactory.getLogger(RoomServiceClient.class);
    private final RestClient restClient;

    public RoomServiceClient(RestClient gatewayRestClient) {
        this.restClient = gatewayRestClient;
    }

    public void updateRoomStatus(Long roomId, String status) {
        try {
            restClient.patch()
                    .uri("/api/rooms/{id}/status", roomId)
                    .body(Map.of("status", status))
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            log.error("Impossible de mettre à jour le statut de la chambre {} vers {} : {}", roomId, status, e.getMessage());
        }
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

    public FullRoomInfo getFullRoomById(Long roomId) {
        try {
            return restClient.get()
                    .uri("/api/rooms/{id}", roomId)
                    .retrieve()
                    .body(FullRoomInfo.class);
        } catch (HttpClientErrorException.NotFound e) {
            throw new ResourceNotFoundException("Chambre introuvable avec l'identifiant : " + roomId);
        } catch (Exception e) {
            throw new RuntimeException("Impossible de contacter le service des chambres : " + e.getMessage());
        }
    }

    public List<FullRoomInfo> getAvailableRooms(String type) {
        try {
            String uri = "/api/rooms?status=AVAILABLE" + (type != null ? "&type=" + type : "");
            return restClient.get()
                    .uri(uri)
                    .retrieve()
                    .body(new ParameterizedTypeReference<>() {});
        } catch (Exception e) {
            throw new RuntimeException("Impossible de contacter le service des chambres : " + e.getMessage());
        }
    }
}
