# Client API Contract

## Objectif

Ce dossier contient le contrat commun backend/frontend pour le module Client.

Il doit être validé avant le développement parallèle du backend et du frontend.

## Stories couvertes

| Story | Fichier |
|---|---|
| HMS-C-01 | client-scope.md |
| HMS-C-02 | client-dtos.md |
| HMS-C-03 | client-endpoints.md |
| HMS-C-04 | client-business-rules.md |

## Décisions principales

- Le nom technique du module est Client.
- Le nom affiché dans l'interface est Clients.
- L'API utilise `/api/clients`.
- Au moins une identification est obligatoire (email, CIN, passeport ou téléphone).
- Les valeurs de champs sont en français dans l'interface, en anglais dans l'API.
- La suppression est logique (soft delete via `active = false`).
- Un client désactivé ne peut pas être utilisé pour une nouvelle réservation.
- La sécurité JWT est temporairement exclue de cette phase.

## Utilisation par le backend

Le backend doit implémenter les DTOs, endpoints et règles métier décrits dans ce dossier.

## Utilisation par le frontend

Le frontend doit créer ses types TypeScript, validations Zod et appels API à partir de ce contrat.

## Dépendances inter-modules

- `GET /api/clients/{id}/reservations` est un stub en V1 — sera câblé au `reservation-service` lors de son implémentation.
- Le `reservation-service` devra vérifier que `client.active = true` avant toute nouvelle réservation.
