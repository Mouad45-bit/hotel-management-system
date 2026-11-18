package com.hotel.management.clientservice;

import com.hotel.management.clientservice.entity.Client;
import com.hotel.management.clientservice.repository.ClientRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;

import java.util.stream.Stream;

@SpringBootApplication
@EnableDiscoveryClient
public class ClientServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ClientServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner start(ClientRepository clientRepository) {
        return args -> {
            Stream.of("Abbas" ,"achraf","nabil","boutaina","ilham").forEach(name -> {
                clientRepository.save(Client.builder().firstName(name).lastName(name).cin(String.valueOf(10+Math.random()*10)).build());
            });

            clientRepository.findAll().forEach(System.out::println);
        };
    }
}
