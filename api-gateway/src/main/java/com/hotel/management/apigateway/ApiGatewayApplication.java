package com.hotel.management.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Point d'entrée de l'API Gateway.
 *
 * Ce microservice sera le point d'entrée unique de l'application.
 * Les clients externes n'appelleront pas directement les services internes.
 */
@SpringBootApplication
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
