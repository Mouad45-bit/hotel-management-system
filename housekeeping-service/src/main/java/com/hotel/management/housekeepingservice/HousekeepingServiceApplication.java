package com.hotel.management.housekeepingservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Entry point of housekeeping-service.
 *
 * This microservice manages cleaning tasks and housekeeping lifecycle actions.
 */
@SpringBootApplication
@EnableDiscoveryClient
public class HousekeepingServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(HousekeepingServiceApplication.class, args);
    }
}
