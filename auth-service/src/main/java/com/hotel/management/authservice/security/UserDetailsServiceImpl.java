package com.hotel.management.authservice.security;

import com.hotel.management.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Implémentation de UserDetailsService utilisée par Spring Security
 * pour charger un utilisateur depuis la base de données lors de l'authentification.
 *
 * Déclarée comme @Service pour être injectée dans SecurityConfig.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Utilisateur introuvable : " + username));
    }
}