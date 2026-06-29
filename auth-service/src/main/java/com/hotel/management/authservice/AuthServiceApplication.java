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

            seedUserIfMissing(
                    userRepository,
                    passwordEncoder,
                    "admin.test",
                    "admin.test@hotel.com",
                    "Admin@123",
                    "Sara",
                    "El Amrani",
                    Role.ADMIN
            );
            seedUserIfMissing(
                    userRepository,
                    passwordEncoder,
                    "manager.test",
                    "manager.test@hotel.com",
                    "Manager@123",
                    "Youssef",
                    "Bennani",
                    Role.MANAGER
            );
            seedUserIfMissing(
                    userRepository,
                    passwordEncoder,
                    "reception.test",
                    "reception.test@hotel.com",
                    "Reception@123",
                    "Salma",
                    "Idrissi",
                    Role.RECEPTIONIST
            );
            seedUserIfMissing(
                    userRepository,
                    passwordEncoder,
                    "housekeeping.test",
                    "housekeeping.test@hotel.com",
                    "Housekeeping@123",
                    "Hamza",
                    "Alaoui",
                    Role.HOUSEKEEPING_AGENT
            );
        };
    }

    private void seedUserIfMissing(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            String username,
            String email,
            String password,
            String firstName,
            String lastName,
            Role role
    ) {
        if (userRepository.existsByUsername(username)) {
            return;
        }

        User user = User.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .firstName(firstName)
                .lastName(lastName)
                .role(role)
                .build();

        userRepository.save(user);
    }
}
