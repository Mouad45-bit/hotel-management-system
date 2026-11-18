package com.hotel.management.invoiceservice.service.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.hotel.management.invoiceservice.dto.external.ClientSummaryResponse;
import com.hotel.management.invoiceservice.exception.InvoiceBusinessException;
import com.hotel.management.invoiceservice.exception.InvoiceNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

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
            JsonNode node = restClient.get()
                    .uri(clientServiceUrl + "/api/clients/{clientId}", clientId)
                    .retrieve()
                    .body(JsonNode.class);
            if (node != null) {
                String fullName = node.path("firstName").asText("") + " " + node.path("lastName").asText("");
                return new ClientSummaryResponse(node.path("id").asLong(), fullName.trim());
            }
        } catch (HttpClientErrorException.NotFound ex) {
            throw new InvoiceNotFoundException("Client not found with id: " + clientId);
        }

        throw new InvoiceBusinessException("Client service returned an empty response for client: " + clientId);
    }
}
