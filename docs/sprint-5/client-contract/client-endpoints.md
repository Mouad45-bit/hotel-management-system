Définir les endpoints REST Client
=======================================

Objectif
-----------------

Définir les routes REST utilisées par le frontend pour gérer les clients.

Tous les appels frontend doivent passer par l'API Gateway.

Base URL frontend :

```
http://localhost:8080/api/clients
```

Endpoints retenus
-----------------

| Méthode | Endpoint | Description |
| --- | --- | --- |
| POST | /api/clients | Créer un client |
| GET | /api/clients | Lister les clients (actifs par défaut) |
| GET | /api/clients/{id} | Consulter le détail d'un client |
| PUT | /api/clients/{id} | Modifier un client |
| DELETE | /api/clients/{id} | Désactiver un client (soft delete) |
| PATCH | /api/clients/{id}/activate | Réactiver un client |
| PATCH | /api/clients/{id}/deactivate | Désactiver un client explicitement |
| GET | /api/clients/search | Rechercher des clients par mot-clé |
| GET | /api/clients/{id}/reservations | Lister les réservations d'un client (stub V1) |
| GET | /api/clients/ping | Vérifier la disponibilité du service |

Query params de recherche
-------------------------

Endpoint :

```
GET /api/clients
```

Query params disponibles :

| Paramètre | Exemple | Description |
| --- | --- | --- |
| active | true / false | Filtre par statut actif/inactif |
| search | dupont | Recherche textuelle (nom, prénom, email, CIN) |

Exemples :

```
GET /api/clients                        → clients actifs
GET /api/clients?active=false           → clients inactifs
GET /api/clients/search?keyword=dupont  → recherche libre
```

Codes HTTP attendus
-------------------

| Cas | Code |
| --- | --- |
| Création réussie | 201 |
| Lecture réussie | 200 |
| Modification réussie | 200 |
| Désactivation réussie | 200 |
| Réactivation réussie | 200 |
| Données invalides | 400 |
| Aucune identification fournie | 400 |
| Client introuvable | 404 |
| Email / CIN / passeport déjà utilisé | 409 |
| Erreur serveur | 500 |

Format d'erreur standard
------------------------

```json
{
  "timestamp": "2026-06-21T10:00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Au moins un identifiant est requis (email, CIN, passeport ou téléphone)",
  "path": "/api/clients"
}
```

Format d'erreur de validation (champs)
---------------------------------------

```json
{
  "timestamp": "2026-06-21T10:00:00",
  "status": 400,
  "error": "Validation Failed",
  "message": "Validation échouée",
  "path": "/api/clients",
  "fieldErrors": {
    "firstName": "Le prénom est obligatoire",
    "email": "Format email invalide"
  }
}
```

Sécurité temporaire
-------------------

Dans cette phase, les routes Client sont temporairement publiques pour accélérer la démonstration.

La sécurisation par JWT sera reprise plus tard.

Acceptance Criteria
-------------------

- Les endpoints sont documentés.
- Les méthodes HTTP sont validées.
- Les query params sont définis.
- Les codes HTTP sont définis.
- Le frontend peut commencer son service API.
- Le binôme B peut câbler reservation-service sur ces endpoints.
