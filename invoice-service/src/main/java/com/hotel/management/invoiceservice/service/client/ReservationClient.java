package com.hotel.management.invoiceservice.service.client;

import com.hotel.management.invoiceservice.dto.external.ReservationSummaryResponse;
import com.hotel.management.invoiceservice.exception.InvoiceBusinessException;
import com.hotel.management.invoiceservice.exception.InvoiceNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Component
public class ReservationClient {

    private final RestClient restClient;
    private final String reservationServiceUrl;

    public ReservationClient(RestClient.Builder restClientBuilder,
                             @Value("${reservation.service.url:${RESERVATION_SERVICE_URL:http://reservation-service:8084}}") String reservationServiceUrl) {
        this.restClient = restClientBuilder.build();
        this.reservationServiceUrl = reservationServiceUrl;
    }

    public ReservationSummaryResponse findSummaryById(Long reservationId) {
        try {
            ReservationSummaryResponse response = restClient.get()
                    .uri(reservationServiceUrl + "/api/reservations/{reservationId}", reservationId)
                    .retrieve()
                    .body(ReservationSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (HttpClientErrorException.NotFound ex) {
            throw new InvoiceNotFoundException("Reservation not found with id: " + reservationId);
        }

        throw new InvoiceBusinessException("Reservation service returned an empty response for reservation: " + reservationId);
    }
}
