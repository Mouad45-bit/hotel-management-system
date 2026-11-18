Définir les DTOs du module Client
=======================================

Objectif
--------------------------------------

Définir les objets JSON échangés entre le frontend et le backend.

CreateClientRequest
--------------------------------------

Utilisé par :

```
POST /api/clients
{
  "firstName": "Mohamed",
  "lastName": "Benali",
  "email": "m.benali@email.com",
  "phone": "0661234567",
  "cin": "AB123456",
  "passportNumber": null,
  "nationality": "Marocaine",
  "address": "12 Rue des Orangers, Casablanca",
  "birthDate": "1990-05-15"
}
```

Règles de validation CreateClientRequest
--------------------------------------

| Champ | Obligatoire | Règle |
| --- | --- | --- |
| firstName | Oui | Non vide |
| lastName | Oui | Non vide |
| email | Non* | Format email valide si fourni, unique |
| phone | Non* | Texte libre |
| cin | Non* | Unique si fourni |
| passportNumber | Non* | Unique si fourni |
| nationality | Non | Texte libre |
| address | Non | Texte libre (max 500 chars) |
| birthDate | Non | Date passée (avant aujourd'hui) |

> *Au moins un parmi email, phone, cin ou passportNumber doit être fourni.

UpdateClientRequest
-----------------

Utilisé par :

```
PUT /api/clients/{id}
{
  "firstName": "Mohamed",
  "lastName": "Benali",
  "email": "m.benali@email.com",
  "phone": "0661234567",
  "cin": "AB123456",
  "passportNumber": null,
  "nationality": "Marocaine",
  "address": "15 Rue des Orangers, Casablanca",
  "birthDate": "1990-05-15"
}
```

Mêmes règles de validation que CreateClientRequest.

ClientResponse
------------

Retourné par l'API.

```json
{
  "id": 1,
  "firstName": "Mohamed",
  "lastName": "Benali",
  "email": "m.benali@email.com",
  "phone": "0661234567",
  "cin": "AB123456",
  "passportNumber": null,
  "nationality": "Marocaine",
  "address": "12 Rue des Orangers, Casablanca",
  "birthDate": "1990-05-15",
  "active": true,
  "createdAt": "2026-06-21T10:00:00",
  "updatedAt": "2026-06-21T10:00:00"
}
```

PingResponse
-----------------

Utilisé par :

```
GET /api/clients/ping
{
  "service": "client-service",
  "status": "UP",
  "message": "Client Service is running"
}
```

Décisions de nommage
--------------------

| Français | API |
| --- | --- |
| prénom | firstName |
| nom | lastName |
| email | email |
| téléphone | phone |
| CIN | cin |
| numéro de passeport | passportNumber |
| nationalité | nationality |
| adresse | address |
| date de naissance | birthDate |
| actif | active |

Acceptance Criteria
-------------------

- Tous les DTOs sont documentés.
- Les exemples JSON sont disponibles.
- La contrainte "au moins 1 identification" est explicite.
- Le frontend peut créer ses types TypeScript et validations Zod conformes.
- Le backend peut implémenter sans changer le contrat.
- Le reservation-service peut identifier un client par son id.
