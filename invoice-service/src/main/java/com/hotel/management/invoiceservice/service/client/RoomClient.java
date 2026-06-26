package com.hotel.management.invoiceservice.service.client;

import com.hotel.management.invoiceservice.dto.external.RoomSummaryResponse;
import com.hotel.management.invoiceservice.exception.InvoiceBusinessException;
import com.hotel.management.invoiceservice.exception.InvoiceNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

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
                    .uri(roomServiceUrl + "/api/rooms/{roomId}", roomId)
                    .retrieve()
                    .body(RoomSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (HttpClientErrorException.NotFound ex) {
            throw new InvoiceNotFoundException("Room not found with id: " + roomId);
        }

        throw new InvoiceBusinessException("Room service returned an empty response for room: " + roomId);
    }
}
