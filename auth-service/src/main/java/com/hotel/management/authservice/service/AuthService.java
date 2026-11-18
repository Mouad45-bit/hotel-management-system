package com.hotel.management.authservice.service;

import com.hotel.management.authservice.config.JwtService;
import com.hotel.management.authservice.dto.*;
import com.hotel.management.authservice.entity.Role;
import com.hotel.management.authservice.entity.User;
import com.hotel.management.authservice.exception.BusinessException;
import com.hotel.management.authservice.exception.ConflictException;
import com.hotel.management.authservice.exception.ResourceNotFoundException;
import com.hotel.management.authservice.mapper.UserMapper;
import com.hotel.management.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new BadCredentialsException("Identifiants incorrects"));

        if (!user.getActive()) {
            throw new BusinessException("Ce compte est désactivé");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole().name());
        String refreshToken = jwtService.generateRefreshToken(user.getUsername(), user.getRole().name());

        return new LoginResponse(accessToken, refreshToken, "Bearer");
    }

    public LoginResponse refresh(String refreshToken) {
        if (!jwtService.isTokenValid(refreshToken) || !jwtService.isRefreshToken(refreshToken)) {
            throw new BusinessException("Refresh token invalide ou expiré");
        }

        String username = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BusinessException("Utilisateur introuvable"));

        if (!user.getActive()) {
            throw new BusinessException("Ce compte est désactivé");
        }

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), user.getRole().name());
        String newRefreshToken = jwtService.generateRefreshToken(user.getUsername(), user.getRole().name());

        return new LoginResponse(newAccessToken, newRefreshToken, "Bearer");
    }

    public UserResponse getMe(User user) {
        return UserMapper.toResponse(user);
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new ConflictException("Ce nom d'utilisateur est déjà pris");
        }
        if (request.email() != null && !request.email().isBlank() && userRepository.existsByEmail(request.email())) {
            throw new ConflictException("Cet email est déjà utilisé");
        }

        Role role;
        try {
            role = Role.valueOf(request.role());
        } catch (IllegalArgumentException e) {
            throw new BusinessException("Rôle invalide : " + request.role());
        }

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .firstName(request.firstName())
                .lastName(request.lastName())
                .role(role)
                .build();

        return UserMapper.toResponse(userRepository.save(user));
    }

    public List<UserResponse> getAllUsers() {
        return userRepository.findAllByOrderByIdDesc().stream()
                .map(UserMapper::toResponse)
                .toList();
    }

    public UserResponse getUserById(Long id) {
        return UserMapper.toResponse(findUserOrThrow(id));
    }

    @Transactional
    public UserResponse updateUser(Long id, UpdateUserRequest request) {
        User user = findUserOrThrow(id);

        if (request.email() != null && !request.email().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.email())) {
                throw new ConflictException("Cet email est déjà utilisé");
            }
            user.setEmail(request.email());
        }
        if (request.firstName() != null) user.setFirstName(request.firstName());
        if (request.lastName() != null) user.setLastName(request.lastName());
        if (request.role() != null) {
            try {
                user.setRole(Role.valueOf(request.role()));
            } catch (IllegalArgumentException e) {
                throw new BusinessException("Rôle invalide : " + request.role());
            }
        }

        return UserMapper.toResponse(userRepository.save(user));
    }

    @Transactional
    public UserResponse activateUser(Long id) {
        User user = findUserOrThrow(id);
        user.setActive(true);
        return UserMapper.toResponse(userRepository.save(user));
    }

    @Transactional
    public UserResponse deactivateUser(Long id) {
        User user = findUserOrThrow(id);
        user.setActive(false);
        return UserMapper.toResponse(userRepository.save(user));
    }

    @Transactional
    public void changePassword(User user, ChangePasswordRequest request) {
        if (!passwordEncoder.matches(request.oldPassword(), user.getPassword())) {
            throw new BusinessException("L'ancien mot de passe est incorrect");
        }
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
    }

    private User findUserOrThrow(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Utilisateur introuvable avec l'id : " + id));
    }
}
