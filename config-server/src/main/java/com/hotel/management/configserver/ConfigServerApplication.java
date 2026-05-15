package com.hotel.management.configserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;

/**
 * Point d'entrée du config-server.
 *
 * Ce service centralise les fichiers de configuration des microservices.
 * Les futurs services comme auth-service, eureka-server et api-gateway
 * viendront récupérer leurs fichiers YAML ici au démarrage.
 */
@SpringBootApplication
@EnableConfigServer
public class ConfigServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConfigServerApplication.class, args);
    }
}
