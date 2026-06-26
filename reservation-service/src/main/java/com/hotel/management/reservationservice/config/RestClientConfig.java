package com.hotel.management.reservationservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Value("${app.gateway-url:http://localhost:8080}")
    private String gatewayUrl;

    @Bean
    public RestClient gatewayRestClient() {
        return RestClient.builder()
                .baseUrl(gatewayUrl)
                .build();
    }
}
