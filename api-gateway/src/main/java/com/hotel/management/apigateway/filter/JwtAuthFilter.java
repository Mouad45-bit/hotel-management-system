package com.hotel.management.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Filtre JWT pour Spring Cloud Gateway.
 *
 * ── POURQUOI C'EST DIFFÉRENT DE L'AUTH-SERVICE ───────────────────────────────
 *
 * L'auth-service utilise Spring MVC (servlet, bloquant) → OncePerRequestFilter.
 * L'api-gateway utilise Spring WebFlux (réactif, non-bloquant) → GatewayFilter.
 *
 * On ne peut PAS utiliser HttpServletRequest ici.
 * On utilise à la place ServerWebExchange qui expose :
 *   - ServerHttpRequest  (réactif)
 *   - ServerHttpResponse (réactif)
 *
 * ── RÔLE DU FILTRE ───────────────────────────────────────────────────────────
 *
 * Pour chaque requête vers un endpoint protégé :
 *
 *  1. Vérifie la présence du header  "Authorization: Bearer <token>"
 *  2. Valide la signature et l'expiration du JWT (jjwt 0.12.5)
 *  3. Extrait username et role depuis les claims
 *  4. Les injecte en headers internes → X-Auth-Username, X-Auth-Role
 *  5. Les services en aval lisent ces headers (pas le JWT directement)
 *
 * ── IMPORTANT : jjwt 0.12.5 ──────────────────────────────────────────────────
 *
 *  Jwts.parser()                  (plus de parserBuilder())
 *  .verifyWith(SecretKey)         (plus de setSigningKey())
 *  .parseSignedClaims(token)      (plus de parseClaimsJws())
 *  .getPayload()                  (plus de getBody())
 */
@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // ── Étape 1 : vérifier la présence du header Authorization ────────
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Header Authorization manquant", HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "Format Bearer invalide", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            // ── Étape 2 : valider le JWT et extraire les claims ───────────────
            try {
                Claims claims = extractAllClaims(token);

                String username = claims.getSubject();
                String role     = claims.get("role", String.class);

                // ── Étape 3 : propager l'identité aux services en aval ────────
                // Les services métier lisent X-Auth-Username et X-Auth-Role
                // sans avoir besoin de redécoder le JWT eux-mêmes.
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-Auth-Username", username)
                        .header("X-Auth-Role",     role != null ? role : "")
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (Exception e) {
                return onError(exchange, "Token JWT invalide ou expiré", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    // ── Validation JWT — API jjwt 0.12.5 ─────────────────────────────────────

    private Claims extractAllClaims(String token) {
        return Jwts.parser()                   // 0.12.x : parser() sans Builder
                .verifyWith(getSigningKey())    // 0.12.x : verifyWith(SecretKey)
                .build()
                .parseSignedClaims(token)      // 0.12.x : parseSignedClaims()
                .getPayload();                 // 0.12.x : getPayload()
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ── Réponse d'erreur réactive ─────────────────────────────────────────────

    /**
     * En WebFlux, on ne peut pas écrire dans la réponse de façon bloquante.
     * exchange.getResponse().setComplete() retourne un Mono<Void> qui
     * signal à la chaîne réactive que le traitement est terminé.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("X-Error-Message", message);
        return exchange.getResponse().setComplete();
    }

    /**
     * Classe de configuration du filtre.
     * Vide ici mais extensible : on pourrait y ajouter des rôles
     * autorisés par route, des paramètres de bypass, etc.
     */
    public static class Config { }
}