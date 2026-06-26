package com.hotel.management.clientservice.service.client;

import com.hotel.management.clientservice.dto.external.ClientReservationResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

@Component
public class ReservationServiceClient {

    private final RestClient restClient;
    private final String reservationServiceUrl;

    public ReservationServiceClient(
            RestClient.Builder restClientBuilder,
            @Value("${reservation.service.url:${RESERVATION_SERVICE_URL:http://reservation-service:8084}}") String reservationServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.reservationServiceUrl = reservationServiceUrl;
    }

    public List<ClientReservationResponse> getReservationsByClientId(Long clientId) {
        List<ClientReservationResponse> response = restClient.get()
                .uri(reservationServiceUrl + "/api/reservations/client/{clientId}", clientId)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
        return response != null ? response : List.of();
    }
}
