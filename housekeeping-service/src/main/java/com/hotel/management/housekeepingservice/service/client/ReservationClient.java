package com.hotel.management.housekeepingservice.service.client;

import com.hotel.management.housekeepingservice.dto.external.ReservationSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.LocalDate;

@Component
public class ReservationClient {

    private final RestClient restClient;
    private final String reservationServiceUrl;

    public ReservationClient(
            RestClient.Builder restClientBuilder,
            @Value("${reservation.service.url:${RESERVATION_SERVICE_URL:http://reservation-service:8083}}") String reservationServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.reservationServiceUrl = reservationServiceUrl;
    }

    public ReservationSummaryResponse findSummaryById(Long reservationId) {
        try {
            ReservationSummaryResponse response = restClient.get()
                    .uri(reservationServiceUrl + "/api/reservations/{reservationId}/summary", reservationId)
                    .retrieve()
                    .body(ReservationSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (RestClientException ignored) {
            // Temporary fallback while reservation-service summary endpoint is not available.
        }

        return new ReservationSummaryResponse(reservationId, null, "CHECKED_OUT", LocalDate.now());
    }
}
