package com.hotel.management.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Point d'entrée de l'API Gateway.
 *
 * Ce microservice sera le point d'entrée unique de l'application.
 * Les clients externes n'appelleront pas directement les services internes.
 *
 * @EnableDiscoveryClient permet à la Gateway de s'enregistrer dans Eureka
 * et d'utiliser les noms logiques des services comme lb://auth-service.
 */
@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}
