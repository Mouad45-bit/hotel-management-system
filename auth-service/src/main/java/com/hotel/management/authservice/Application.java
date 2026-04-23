package com.hotel.management.authservice;

import com.hotel.management.authservice.entity.Role;
import com.hotel.management.authservice.entity.User;
import com.hotel.management.authservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Point d'entrée de l'auth-service.
 *
 * @EnableDiscoveryClient → s'enregistre dans Eureka au démarrage.
 *
 * Le CommandLineRunner crée un compte ADMIN par défaut au premier démarrage
 * si aucun compte "admin" n'existe en base.
 * À sécuriser ou supprimer en production.
 */
@SpringBootApplication
@EnableDiscoveryClient
@Slf4j
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    CommandLineRunner seedAdmin(UserRepository userRepository,
                                PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                User admin = User.builder()
                        .username("admin")
                        .email("admin@hotel.co")
                        .password(passwordEncoder.encode("admin@1234"))
                        .role(Role.ADMIN)
                        .build();
                userRepository.save(admin);
                log.info(">>> Compte ADMIN créé automatiquement : admin / admin@1234");
            }
        };
    }
}