package com.hotel.management.authservice.entity;

/**
 * Rôles disponibles dans l'application hôtelière.
 * Chaque rôle est préfixé ROLE_ par Spring Security via getAuthorities().
 *
 *  ADMIN → accès complet à tous les services
 *  MANAGER → gestion + rapports, pas d'admin système
 *  RECEPTIONNISTE → réservations, check-in/out, facturation
 *  AGENT_MENAGE → housekeeping uniquement
 *  RH → gestion du personnel uniquement
 */
public enum Role {
    ADMIN,
    MANAGER,
    RECEPTIONNISTE,
    AGENT_MENAGE,
    RH
}