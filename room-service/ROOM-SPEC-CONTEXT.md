# ROOM-SERVICE - BACKEND SPECIFICATIONS ONLY
# Source: hms-v0.txt & pfa_00.pdf
# Objectif : Référence unique pour l'assistant IA afin de valider le code Backend du module Room.

================================================================================
1. ARCHITECTURE & CONFIGURATION
   ================================================================================
- Nom technique du service : room-service
- Port dédié : 8082
- Nom de la base de données (MariaDB) : db_room
- Port de la base : 3308 (mappé sur le host) / 3306 (interne Docker)
- Volume Docker : db-room-data
- URL de la base en Docker : jdbc:mariadb://db-room:3306/db_room
- Configuration centralisée YAML (dans config-server) : room-service.yml
- Le service doit s'enregistrer dans Eureka et charger sa config depuis config-server (spring.cloud.config.import).

================================================================================
2. CONTRAT DE L'API REST (BACKEND CONTRACT)
   ================================================================================
# Prefixe global : /api/rooms
# Tous les appels passent par l'API Gateway.
# Sécurité JWT temporairement désactivée pour la V1 de ce module (endpoints publics pour l'instant).

2.1 Endpoints REST
-----------------------
Méthode | Endpoint                    | Rôle
--------|-----------------------------|-------------------------------------------
POST    | /api/rooms                  | Créer une nouvelle chambre
GET     | /api/rooms                  | Lister et filtrer les chambres
GET     | /api/rooms/{id}             | Détail d'une chambre
PUT     | /api/rooms/{id}             | Modifier les informations permanentes
DELETE  | /api/rooms/{id}             | Suppression logique (active = false)
PATCH   | /api/rooms/{id}/status      | Changer le statut métier
PATCH   | /api/rooms/{id}/activate   | Activer administrativement
PATCH   | /api/rooms/{id}/deactivate | Désactiver administrativement
GET     | /api/rooms/disabled         | Lister les chambres désactivées
GET     | /api/rooms/stats            | Récupérer les statistiques globales
GET     | /api/rooms/{id}/reservation-history | Historique des réservations (futur)
GET     | /api/rooms/ping             | Test technique

2.2 Query Params (pour le filtrage)
---------------------------------------
Paramètre | Type     | Exemple          | Description
----------|----------|------------------|---------------------------------
number    | string   | 101              | Filtre par numéro exact
type      | RoomType | DOUBLE           | Filtre par type
status    | RoomStatus| AVAILABLE       | Filtre par statut
floor     | integer  | 1                | Filtre par étage
capacity  | integer  | 2                | Filtre par capacité minimale
active    | boolean  | true             | Filtre par état administratif

2.3 Enums (Valeurs exactes pour le Backend)
----------------------------
# Les valeurs backend et frontend doivent être strictement identiques (sérialisation JSON).
RoomType :
- SINGLE, DOUBLE, TWIN, SUITE, FAMILY, DELUXE

RoomStatus :
- AVAILABLE, RESERVED, OCCUPIED, CLEANING, MAINTENANCE, OUT_OF_SERVICE

2.4 DTOs (Data Transfer Objects)
---------------------------------
# Tous les DTOs doivent être validés avec les annotations Jakarta Validation (@NotBlank, @NotNull, @Positive, @Min).

CREATE ROOM REQUEST (JSON reçu par POST /api/rooms) :
{
"number": "101",           // String, Obligatoire, Unique
"floor": 1,                // Integer, Obligatoire, >= 0
"type": "DOUBLE",          // RoomType Enum, Obligatoire
"pricePerNight": 650.00,   // BigDecimal, Obligatoire, >= 0
"capacity": 2,             // Integer, Obligatoire, > 0
"status": "AVAILABLE",     // RoomStatus Enum, Obligatoire
"description": "..."       // String, Optionnel
}

UPDATE ROOM REQUEST (JSON reçu par PUT /api/rooms/{id}) :
// Mêmes champs que CreateRoomRequest, mis à jour en bloc.

UPDATE STATUS ROOM REQUEST (JSON reçu par PATCH /api/rooms/{id}/status) :
{
"status": "CLEANING"       // RoomStatus Enum, Obligatoire
}

ROOM RESPONSE (JSON retourné par l'API) :
{
"id": 1,
"number": "101",
"floor": 1,
"type": "DOUBLE",
"pricePerNight": 650.00,
"capacity": 2,
"status": "AVAILABLE",
"description": "Double room with garden view",
"active": true,            // Boolean pour la suppression logique
"createdAt": "2026-05-17T14:30:00",
"updatedAt": "2026-05-17T14:30:00"
}

ROOM STATS RESPONSE (JSON retourné par GET /api/rooms/stats) :
{
"total": 40,
"available": 18,
"occupied": 10,
"reserved": 7,
"cleaning": 3,
"maintenance": 2,
"outOfService": 0
}

================================================================================
3. RÈGLES MÉTIER (BUSINESS RULES)
   ================================================================================
- Le numéro de chambre (number) est obligatoire et strictement unique.
- L'étage (floor) est obligatoire et doit être >= 0.
- La capacité (capacity) est obligatoire et strictement > 0.
- Le prix par nuit (pricePerNight) est obligatoire et >= 0.
- Le type (type) et le statut (status) sont obligatoires.
- Une chambre existante peut être modifiée. Si le numéro change, il doit rester unique.
- La suppression est LOGIQUE : on passe le champ `active` à false. La chambre reste en base, visible seulement via l'endpoint /disabled.
- Une chambre en MAINTENANCE, CLEANING ou OUT_OF_SERVICE ne peut pas être réservée (vérifiée par le futur Reservation Service).
- Conflits métier retournent un code HTTP 409 CONFLICT (ex: numéro déjà pris).
- Ressource introuvable retourne un code HTTP 404 NOT_FOUND.

================================================================================
4. STANDARDS D'ERREURS (API ERROR CONVENTIONS)
   ================================================================================
# Toutes les erreurs doivent suivre le modèle standard via GlobalExceptionHandler.

4.1 Format Erreur Générale (ApiError) :
{
"timestamp": "2026-05-16T14:30:00",
"status": 404,
"error": "NOT_FOUND",      // Code technique (NOT_FOUND, CONFLICT, INTERNAL_SERVER_ERROR)
"message": "Room not found with id: 12",
"path": "/api/rooms/12"
}

4.2 Format Erreur de Validation (ValidationError) :
{
"timestamp": "2026-05-16T14:30:00",
"status": 400,
"error": "VALIDATION_ERROR",
"message": "Validation failed",
"path": "/api/rooms",
"fieldErrors": {
"number": "Room number is required",
"pricePerNight": "Price per night must be positive"
}
}

4.3 Exceptions Métier à implémenter dans room-service :
- ResourceNotFoundException (Mapping: 404 NOT_FOUND)
- ConflictException (Mapping: 409 CONFLICT)
- BusinessException (Mapping: 400 BAD_REQUEST)
- Utiliser @RestControllerAdvice pour un GlobalExceptionHandler.

================================================================================
5. STRATÉGIE GIT & DÉPENDANCES (Pour le contexte de merge)
   ================================================================================
- Branche de travail : feature/binome-a/room-service (à merger dans binome-a/core-flow, puis develop).
- Matrice des dépendances :
    - DÉPEND DE : Aucun autre module pour le CRUD de base (seulement sa propre base db_room).
    - UTILISÉ PAR : Le module Reservation, le module Housekeeping et le module Report.
- Règle d'architecture : Le module ne doit jamais lire la base de données d'un autre microservice (Database-per-service). Pour interagir avec un autre service, utiliser des appels REST via l'API Gateway.

================================================================================
END OF BACKEND-ROOM-SPEC
================================================================================
