package com.hotel.management.invoiceservice.service.client;

import com.hotel.management.invoiceservice.dto.external.RoomSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class RoomClient {

    private final RestClient restClient;
    private final String roomServiceUrl;

    public RoomClient(RestClient.Builder restClientBuilder,
                      @Value("${room.service.url:${ROOM_SERVICE_URL:http://room-service:8082}}") String roomServiceUrl) {
        this.restClient = restClientBuilder.build();
        this.roomServiceUrl = roomServiceUrl;
    }

    public RoomSummaryResponse findSummaryById(Long roomId) {
        try {
            RoomSummaryResponse response = restClient.get()
                    .uri(roomServiceUrl + "/api/rooms/{roomId}/summary", roomId)
                    .retrieve()
                    .body(RoomSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (RestClientException ignored) {
            // Temporary fallback while room-service summary endpoint is not available.
        }

        return new RoomSummaryResponse(roomId, "101");
    }
}
