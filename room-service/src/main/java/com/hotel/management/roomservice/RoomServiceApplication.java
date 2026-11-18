package com.hotel.management.roomservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Entry point of room-service.
 *
 * This microservice manages hotel rooms.
 *
 * It will be responsible for:
 * - room creation
 * - room update
 * - room status management
 * - room inventory consultation
 *
 * It is not responsible for:
 * - reservations
 * - invoices
 * - authentication
 */
@SpringBootApplication
@EnableDiscoveryClient
public class RoomServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(RoomServiceApplication.class, args);
    }
}
