package com.hotel.management.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Point d'entrée de l'API Gateway.
 *
 * @EnableDiscoveryClient → s'enregistre dans Eureka et peut résoudre
 * les noms de services (lb://auth-service, lb://chambre-service…)
 * via le load balancer intégré à Spring Cloud Gateway.
 *
 * Toute la configuration des routes est dans api-gateway.yml
 * (servi par le config-server), pas ici.
 */
@SpringBootApplication
@EnableDiscoveryClient
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}