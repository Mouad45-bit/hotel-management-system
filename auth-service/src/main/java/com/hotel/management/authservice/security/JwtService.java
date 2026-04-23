package com.hotel.management.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service de gestion des tokens JWT.
 *
 * IMPORTANT — Différences API jjwt 0.12.x vs 0.11.x :
 *
 *  Génération :
 *    0.11.x → .setClaims()  .setSubject()  .setIssuedAt()  .setExpiration()  .signWith(key, algo)
 *    0.12.x → .claims()     .subject()     .issuedAt()     .expiration()     .signWith(key)
 *
 *  Validation :
 *    0.11.x → Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody()
 *    0.12.x → Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload()
 */
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;          // 86400000 ms = 24h

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;      // 604800000 ms = 7 jours

    // ── Extraction ───────────────────────────────────────────────────────────

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    // ── Génération ───────────────────────────────────────────────────────────

    /**
     * Génère le access token (24h).
     * Ajoute le rôle dans les claims pour que la Gateway puisse le lire
     * et le transmettre aux services en aval via X-Auth-Role.
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(a -> a.getAuthority().replace("ROLE_", ""))
                .orElse("");
        extraClaims.put("role", role);
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Génère le refresh token (7 jours).
     * Sans claims supplémentaires — uniquement pour renouveler le access token.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims,
                              UserDetails userDetails,
                              long expiration) {
        return Jwts.builder()
                .claims(extraClaims)                                          // 0.12.x
                .subject(userDetails.getUsername())                           // 0.12.x
                .issuedAt(new Date(System.currentTimeMillis()))               // 0.12.x
                .expiration(new Date(System.currentTimeMillis() + expiration))// 0.12.x
                .signWith(getSigningKey())                                     // 0.12.x — algo déduit de la clé
                .compact();
    }

    // ── Validation ───────────────────────────────────────────────────────────

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    // ── Utilitaires internes ─────────────────────────────────────────────────

    private Claims extractAllClaims(String token) {
        return Jwts.parser()                      // 0.12.x — plus de parserBuilder()
                .verifyWith(getSigningKey())       // 0.12.x — plus de setSigningKey()
                .build()
                .parseSignedClaims(token)         // 0.12.x — plus de parseClaimsJws()
                .getPayload();                    // 0.12.x — plus de getBody()
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public long getExpirationInSeconds() {
        return jwtExpiration / 1000;
    }
}