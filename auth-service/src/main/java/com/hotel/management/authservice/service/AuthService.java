package com.hotel.management.authservice.service;

import com.hotel.management.authservice.dto.AuthRequest;
import com.hotel.management.authservice.dto.AuthResponse;
import com.hotel.management.authservice.dto.RegisterRequest;
import com.hotel.management.authservice.entity.User;
import com.hotel.management.authservice.repository.UserRepository;
import com.hotel.management.authservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Logique métier de l'authentification.
 *
 *  register() → crée un compte et retourne directement les tokens
 *  login() → valide les credentials via AuthenticationManager et retourne les tokens
 *  refreshToken() → renouvelle le access token à partir d'un refresh token valide
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository        userRepository;
    private final PasswordEncoder       passwordEncoder;
    private final JwtService            jwtService;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username déjà utilisé : " + request.getUsername());
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email déjà utilisé : " + request.getEmail());
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(user);
        return buildResponse(user);
    }

    public AuthResponse login(AuthRequest request) {
        // Lance BadCredentialsException automatiquement si username/password invalides
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalStateException("Utilisateur introuvable après authentification"));

        return buildResponse(user);
    }

    public AuthResponse refreshToken(String refreshToken) {
        String username = jwtService.extractUsername(refreshToken);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur introuvable"));

        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new IllegalArgumentException("Refresh token invalide ou expiré");
        }

        return buildResponse(user);
    }

    private AuthResponse buildResponse(User user) {
        return AuthResponse.builder()
                .accessToken(jwtService.generateToken(user))
                .refreshToken(jwtService.generateRefreshToken(user))
                .expiresIn(jwtService.getExpirationInSeconds())
                .username(user.getUsername())
                .role(user.getRole().name())
                .build();
    }
}