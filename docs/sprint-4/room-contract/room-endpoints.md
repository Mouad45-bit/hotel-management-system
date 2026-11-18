Définir les endpoints REST Room
=======================================

Objectif
-----------------

Définir les routes REST utilisées par le frontend pour gérer les chambres.

Tous les appels frontend doivent passer par l’API Gateway.

Base URL frontend :

```
http://localhost:8080/api/rooms
```

Endpoints retenus
-----------------

| Méthode | Endpoint | Description |
| --- | --- | --- |
| POST | /api/rooms | Créer une chambre |
| GET | /api/rooms | Lister les chambres |
| GET | /api/rooms/{id} | Consulter le détail d'une chambre |
| PUT | /api/rooms/{id} | Modifier une chambre |
| DELETE | /api/rooms/{id} | Supprimer ou désactiver une chambre |
| PATCH | /api/rooms/{id}/status | Changer le statut d'une chambre |
| GET | /api/rooms/stats | Récupérer les statistiques des chambres |

Query params de recherche
-------------------------

Endpoint :

```
GET /api/rooms
```

Query params disponibles :

| Paramètre | Exemple | Description |
| --- | --- | --- |
| number | 101 | Recherche par numéro |
| type | DOUBLE | Filtre par type |
| status | AVAILABLE | Filtre par statut |
| floor | 1 | Filtre par étage |
| capacity | 2 | Filtre par capacité minimale |

Exemple :

```
GET /api/rooms?type=DOUBLE&status=AVAILABLE&floor=1
```

Codes HTTP attendus
-------------------

| Cas | Code |
| --- | --- |
| Création réussie | 201 |
| Lecture réussie | 200 |
| Modification réussie | 200 |
| Suppression réussie | 204 |
| Données invalides | 400 |
| Chambre introuvable | 404 |
| Numéro déjà utilisé | 409 |
| Erreur serveur | 500 |

Format d'erreur standard
------------------------

```
{  
  "timestamp": 
  "2026-05-17T14:30:00",  
  "status": 400,  
  "error": "Bad Request",  
  "message": "Room number is required",  
  "path": "/api/rooms"
}
```

Sécurité temporaire
-------------------

Dans cette phase, les routes Room sont temporairement publiques pour accélérer la démonstration.

La sécurisation par JWT sera reprise plus tard.

Acceptance Criteria
-------------------

-   Les endpoints sont documentés.
-   Les méthodes HTTP sont validées.
-   Les query params sont définis.
-   Les codes HTTP sont définis.
-   Le frontend peut commencer son service API.
