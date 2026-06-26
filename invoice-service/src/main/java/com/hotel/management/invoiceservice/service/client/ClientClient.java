package com.hotel.management.invoiceservice.service.client;

import com.hotel.management.invoiceservice.dto.external.ClientSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class ClientClient {

    private final RestClient restClient;
    private final String clientServiceUrl;

    public ClientClient(RestClient.Builder restClientBuilder,
                        @Value("${client.service.url:${CLIENT_SERVICE_URL:http://client-service:8083}}") String clientServiceUrl) {
        this.restClient = restClientBuilder.build();
        this.clientServiceUrl = clientServiceUrl;
    }

    public ClientSummaryResponse findSummaryById(Long clientId) {
        try {
            ClientSummaryResponse response = restClient.get()
                    .uri(clientServiceUrl + "/api/clients/{clientId}/summary", clientId)
                    .retrieve()
                    .body(ClientSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (RestClientException ignored) {
            // Temporary fallback while client-service is not available.
        }

        return new ClientSummaryResponse(clientId, "Temporary Client");
    }
}
