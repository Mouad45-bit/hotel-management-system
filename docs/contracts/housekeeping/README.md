# Contrat fonctionnel et API Housekeeping

## Objectif

Le module Housekeeping pilote les tâches de nettoyage et de remise en état des chambres. Il répond à la question opérationnelle suivante : quelles chambres doivent être nettoyées, par qui et dans quel état ?

## Périmètre V1

- Vue opérationnelle du jour pour les managers, administrateurs et agents housekeeping.
- Liste filtrable et paginée des tâches.
- Création manuelle d'une tâche par `MANAGER` ou `ADMIN`.
- Consultation du détail d'une tâche.
- Affectation d'une tâche à un agent existant.
- Démarrage, terminaison et annulation d'une tâche.
- Vue `My tasks` limitée aux tâches de l'agent connecté.
- Historique de nettoyage par chambre.
- Simulation frontend des dépendances Room, Staff et Reservation si les services ne sont pas prêts.

## Fonctionnalités incluses

- Création manuelle d'une tâche au statut `TODO`.
- Gestion des statuts `TODO`, `IN_PROGRESS`, `DONE`, `CANCELLED`.
- Gestion des types `STANDARD_CLEANING`, `DEEP_CLEANING`, `INSPECTION`, `LIGHT_MAINTENANCE`.
- Gestion des priorités `LOW`, `MEDIUM`, `HIGH`, `URGENT`.
- Actions métier sécurisées par confirmation UI.
- Query params compatibles avec filtres frontend.
- Mocks réalistes pour tâches automatiques après check-out, agents et chambres.

## Fonctionnalités exclues temporairement

- Suppression physique d'une tâche.
- Synchronisation temps réel.
- Gestion détaillée des stocks de linge et produits.
- Checklists de nettoyage par type de chambre.
- Photos, signatures ou preuves de passage.
- Gestion avancée des rôles côté frontend au-delà des règles d'affichage V1.

## Enums

### HousekeepingTaskStatus

- `TODO`
- `IN_PROGRESS`
- `DONE`
- `CANCELLED`

### HousekeepingTaskType

- `STANDARD_CLEANING`
- `DEEP_CLEANING`
- `INSPECTION`
- `LIGHT_MAINTENANCE`

### Priority

- `LOW`
- `MEDIUM`
- `HIGH`
- `URGENT`

## DTOs

### HousekeepingTask

```json
{
  "id": 1,
  "roomId": 301,
  "roomNumber": "301",
  "reservationId": 905,
  "assignedAgentId": 101,
  "assignedAgentName": "Nadia El Amrani",
  "type": "STANDARD_CLEANING",
  "status": "TODO",
  "priority": "HIGH",
  "scheduledDate": "2026-06-19",
  "startedAt": null,
  "completedAt": null,
  "cancelledAt": null,
  "cancellationReason": null,
  "notes": "Nettoyage après check-out",
  "createdAt": "2026-06-19T09:00:00",
  "updatedAt": "2026-06-19T09:00:00"
}
```

### CreateHousekeepingTaskRequest

```json
{
  "roomId": 301,
  "reservationId": 905,
  "assignedAgentId": 101,
  "type": "STANDARD_CLEANING",
  "priority": "HIGH",
  "scheduledDate": "2026-06-19",
  "notes": "Nettoyage après check-out"
}
```

### UpdateHousekeepingTaskRequest

```json
{
  "type": "DEEP_CLEANING",
  "priority": "URGENT",
  "scheduledDate": "2026-06-19",
  "notes": "Intervention prioritaire"
}
```

### AssignHousekeepingTaskRequest

```json
{
  "assignedAgentId": 101
}
```

### CancelHousekeepingTaskRequest

```json
{
  "reason": "Chambre bloquée pour maintenance"
}
```

### PageResponse<T>

```json
{
  "content": [],
  "page": 0,
  "size": 20,
  "totalElements": 0,
  "totalPages": 0,
  "last": true
}
```

## Endpoints REST

| Méthode | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/housekeeping-tasks` | Créer une tâche manuelle au statut `TODO`. |
| `GET` | `/api/housekeeping-tasks` | Lister les tâches avec filtres et pagination. |
| `GET` | `/api/housekeeping-tasks/{id}` | Récupérer le détail d'une tâche. |
| `PUT` | `/api/housekeeping-tasks/{id}` | Modifier les champs éditables d'une tâche non finale. |
| `PATCH` | `/api/housekeeping-tasks/{id}/assign` | Affecter la tâche à un agent. |
| `PATCH` | `/api/housekeeping-tasks/{id}/start` | Passer la tâche de `TODO` à `IN_PROGRESS`. |
| `PATCH` | `/api/housekeeping-tasks/{id}/complete` | Passer la tâche de `IN_PROGRESS` à `DONE`. |
| `PATCH` | `/api/housekeeping-tasks/{id}/cancel` | Passer la tâche de `TODO` ou `IN_PROGRESS` à `CANCELLED`. |
| `GET` | `/api/housekeeping-tasks/room/{roomId}` | Lister l'historique d'une chambre. |
| `GET` | `/api/housekeeping-tasks/agent/{agentId}` | Lister les tâches d'un agent. |
| `GET` | `/api/housekeeping-tasks/today` | Lister les tâches planifiées du jour. |
| `GET` | `/api/housekeeping-tasks/ping` | Vérifier la disponibilité du service. |

## Query params

`GET /api/housekeeping-tasks` accepte :

- `status`: valeur `HousekeepingTaskStatus`.
- `type`: valeur `HousekeepingTaskType`.
- `priority`: valeur `Priority`.
- `roomId`: identifiant positif de chambre.
- `agentId`: identifiant positif d'agent.
- `scheduledDate`: date `YYYY-MM-DD`.
- `page`: index de page, défaut `0`.
- `size`: taille de page, défaut `20`.
- `sort`: format `field,direction`, exemple `scheduledDate,asc`.

## Règles métier

- Une tâche doit être liée à une chambre existante.
- Une tâche peut être créée automatiquement après check-out, mais la V1 frontend simule ce cas avec des mocks.
- Une tâche manuelle peut être créée par `MANAGER` ou `ADMIN`.
- Une tâche assignée doit référencer un employé existant.
- Un agent ne voit que ses tâches dans `My tasks`.
- Une tâche `DONE` ne peut pas revenir à `TODO`.
- Terminer une tâche de nettoyage peut remettre la chambre à `AVAILABLE`.
- Une chambre en nettoyage ne doit pas être vendue comme disponible.
- Pas de suppression physique en V1.

## Transitions de statut

| État source | Action | État cible |
| --- | --- | --- |
| `TODO` | assign | `TODO` |
| `TODO` | start | `IN_PROGRESS` |
| `TODO` | cancel | `CANCELLED` |
| `IN_PROGRESS` | complete | `DONE` |
| `IN_PROGRESS` | cancel | `CANCELLED` |
| `DONE` | aucune | final |
| `CANCELLED` | aucune | final |

L'assignation ne change pas forcément le statut. `DONE` et `CANCELLED` sont finaux.

## Format d'erreur attendu

```json
{
  "timestamp": "2026-06-19T10:00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "La chambre est obligatoire.",
  "path": "/api/housekeeping-tasks",
  "fieldErrors": {
    "roomId": "La chambre est obligatoire."
  }
}
```

## Stratégie temporaire dépendances

- `room-service` non prêt : utiliser une liste frontend de chambres simulées avec `roomId`, `roomNumber`, `status` et disponibilité.
- `staff-service` non prêt : utiliser une liste frontend d'agents housekeeping simulés.
- `reservation-service` non prêt : simuler `reservationId` pour représenter les tâches créées après check-out.
- Quand les services seront disponibles, remplacer uniquement les sources de données dans `housekeepingApi.ts` sans modifier les composants métier.
