package com.hotel.management.eurekaserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

/**
 * Point d'entrée du eureka-server.
 *
 * Ce service joue le rôle de service discovery.
 * Les futurs microservices comme auth-service, api-gateway,
 * room-service ou reservation-service viendront s'enregistrer ici.
 *
 * Le eureka-server doit démarrer après le config-server,
 * car sa configuration est centralisée dans config-server.
 */
@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(EurekaServerApplication.class, args);
    }
}
