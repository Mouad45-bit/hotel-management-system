package com.hotel.management.reservationservice.client;

import com.hotel.management.reservationservice.client.dto.ClientInfo;
import com.hotel.management.reservationservice.exception.ResourceNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Component
public class ClientServiceClient {

    private final RestClient restClient;

    public ClientServiceClient(RestClient gatewayRestClient) {
        this.restClient = gatewayRestClient;
    }

    public ClientInfo getClientById(Long clientId) {
        try {
            return restClient.get()
                    .uri("/api/clients/{id}", clientId)
                    .retrieve()
                    .body(ClientInfo.class);
        } catch (HttpClientErrorException.NotFound e) {
            throw new ResourceNotFoundException("Client introuvable avec l'identifiant : " + clientId);
        } catch (Exception e) {
            throw new RuntimeException("Impossible de contacter le service clients : " + e.getMessage());
        }
    }
}
