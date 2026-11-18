Définir les DTOs du module Room
=======================================

Objectif
--------------------------------------

Définir les objets JSON échangés entre le frontend et le backend.

CreateRoomRequest
--------------------------------------

Utilisé par :

```
POST /api/rooms
{  
  "number": "101",  
  "floor": 1,  
  "type": "DOUBLE",  
  "pricePerNight": 650.00,  
  "capacity": 2,  
  "status": "AVAILABLE",  
  "description": "Double room with garden view"
}
```

Règles de validation CreateRoomRequest
--------------------------------------

| Champ | Obligatoire | Règle |
| --- | --- | --- |
| number | Oui | Non vide, unique |
| floor | Oui | Supérieur ou égal à 0 |
| type | Oui | Valeur de RoomType |
| pricePerNight | Oui | Supérieur ou égal à 0 |
| capacity | Oui | Supérieur à 0 |
| status | Oui | Valeur de RoomStatus |
| description | Non | Texte libre |

UpdateRoomRequest
-----------------

Utilisé par :

```
PUT /api/rooms/{id}
{  
  "number": "101",  
  "floor": 1,  
  "type": "DOUBLE",  
  "pricePerNight": 700.00,  
  "capacity": 2,  
  "status": "AVAILABLE",  
  "description": "Updated room description"
}
```

UpdateStatusRoomRequest
-----------------------

Utilisé par :

```
PATCH /api/rooms/{id}/status
{  
  "status": "CLEANING"
}
```

RoomResponse
------------

Retourné par l'API.

```
{  
  "id": 1,  
  "number": "101",  
  "floor": 1,  
  "type": "DOUBLE",  
  "pricePerNight": 650.00,  
  "capacity": 2,  
  "status": "AVAILABLE",  
  "description": "Double room with garden view",  
  "active": true,  
  "createdAt": "2026-05-17T14:30:00",  
  "updatedAt": "2026-05-17T14:30:00"
}
```

RoomStatsResponse
-----------------

Utilisé par :

```
GET /api/rooms/stats
{  
  "total": 40,  
  "available": 18,  
  "occupied": 10,  
  "reserved": 7,  
  "cleaning": 3,  
  "maintenance": 2,  
  "outOfService": 0
}
```

Décisions de nommage
--------------------

| Français | API |
| --- | --- |
| numéro | number |
| étage | floor |
| type | type |
| prix par nuit | pricePerNight |
| capacité | capacity |
| statut | status |
| description | description |

Acceptance Criteria
-------------------

-   Tous les DTOs sont documentés.
-   Les exemples JSON sont disponibles.
-   Le frontend peut créer des mocks conformes.
-   Le backend peut implémenter sans changer le contrat.
