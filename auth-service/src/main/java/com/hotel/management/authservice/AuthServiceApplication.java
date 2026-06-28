package com.hotel.management.authservice;

import com.hotel.management.authservice.entity.Role;
import com.hotel.management.authservice.entity.User;
import com.hotel.management.authservice.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner seedAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin")) {
                User admin = User.builder()
                        .username("admin")
                        .email("admin@hotel.com")
                        .password(passwordEncoder.encode("admin123"))
                        .firstName("Admin")
                        .lastName("System")
                        .role(Role.ADMIN)
                        .build();
                userRepository.save(admin);
            }

            if (!userRepository.existsByUsername("mouad")) {
                User mouad = User.builder()
                        .username("mouad")
                        .email("mouad@hotel.com")
                        .password(passwordEncoder.encode("mouad"))
                        .firstName("Mouad")
                        .lastName("User")
                        .role(Role.ADMIN)
                        .build();
                userRepository.save(mouad);
            }
        };
    }
}
