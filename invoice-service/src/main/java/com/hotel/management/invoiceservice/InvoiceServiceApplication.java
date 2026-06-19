package com.hotel.management.invoiceservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Entry point of invoice-service.
 *
 * This microservice manages invoices and payment lifecycle actions.
 */
@SpringBootApplication
@EnableDiscoveryClient
public class InvoiceServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(InvoiceServiceApplication.class, args);
    }
}
