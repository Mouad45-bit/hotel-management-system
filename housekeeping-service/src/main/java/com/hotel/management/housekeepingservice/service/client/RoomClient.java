package com.hotel.management.housekeepingservice.service.client;

import com.hotel.management.housekeepingservice.dto.external.RoomSummaryResponse;
import com.hotel.management.housekeepingservice.exception.HousekeepingBusinessException;
import com.hotel.management.housekeepingservice.exception.HousekeepingTaskNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Component
public class RoomClient {

    private final RestClient restClient;
    private final String roomServiceUrl;

    public RoomClient(
            RestClient.Builder restClientBuilder,
            @Value("${room.service.url:${ROOM_SERVICE_URL:http://room-service:8082}}") String roomServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.roomServiceUrl = roomServiceUrl;
    }

    public RoomSummaryResponse findSummaryById(Long roomId) {
        try {
            RoomSummaryResponse response = restClient.get()
                    .uri(roomServiceUrl + "/api/rooms/{roomId}", roomId)
                    .retrieve()
                    .body(RoomSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (HttpClientErrorException.NotFound exception) {
            throw new HousekeepingTaskNotFoundException("Room not found with id: " + roomId);
        }

        throw new HousekeepingBusinessException("Room service returned an empty response for room: " + roomId);
    }

    public void markRoomAvailable(Long roomId) {
        restClient.patch()
                .uri(roomServiceUrl + "/api/rooms/{roomId}/status", roomId)
                .body(Map.of("status", "AVAILABLE"))
                .retrieve()
                .toBodilessEntity();
    }

    public void markRoomHousekeeping(Long roomId) {
        restClient.patch()
                .uri(roomServiceUrl + "/api/rooms/{roomId}/status", roomId)
                .body(Map.of("status", "CLEANING"))
                .retrieve()
                .toBodilessEntity();
    }
}
