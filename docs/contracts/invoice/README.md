# Invoice API Contract

## Objectif

Ce document contient le contrat commun backend/frontend pour le module Invoice.

Il doit être validé avant le développement parallèle du backend et du frontend.

Le module Invoice gère les factures et les paiements liés aux réservations.

Il répond à la question métier :

```text
Combien le client doit payer, pour quelle réservation et avec quel statut financier ?
```

---

# 1. Périmètre fonctionnel du module Invoice

## Responsabilité principale

Le module Invoice est responsable de :

- générer une facture depuis une réservation ;
- consulter la liste des factures ;
- consulter le détail financier d’une facture ;
- rechercher une facture par numéro ;
- consulter les factures d’un client ;
- consulter la facture liée à une réservation ;
- émettre une facture ;
- marquer une facture comme payée ;
- annuler une facture avec motif ;
- rembourser une facture payée ;
- fournir les données nécessaires à l’aperçu imprimable côté frontend.

## Fonctionnalités incluses dans la V1

- Générer une facture depuis une réservation.
- Afficher la liste des factures.
- Filtrer les factures par statut, client, réservation et période.
- Afficher le détail d’une facture.
- Afficher les lignes de facture.
- Émettre une facture.
- Marquer une facture comme payée.
- Annuler une facture avec motif.
- Rembourser une facture payée.
- Afficher les factures d’un client.
- Afficher la facture d’une réservation.
- Préparer les données nécessaires pour l’impression frontend.

## Fonctionnalités exclues temporairement

- Paiement en ligne réel.
- Paiement partiel.
- Multi-devise.
- Génération PDF côté backend.
- Envoi automatique de facture par email.
- Avoir comptable avancé.
- Export comptable.
- Intégration avec une passerelle bancaire.
- Gestion avancée des taxes multiples.
- Sécurité JWT complète.
- Permissions par rôle.

## Décision V1 sur la génération

Dans la V1, une facture est générée à partir d’une réservation déjà terminée.

Le scénario cible est :

```text
Check-out -> Generate invoice -> Issue invoice -> Pay invoice
```

Si `reservation-service` n’est pas encore terminé, le backend Invoice peut utiliser des DTOs externes minimaux ou des mocks temporaires.

## Décision V1 sur le paiement

Dans la V1, le paiement est simple.

Une facture passe directement de :

```text
ISSUED -> PAID
```

Il n’y a pas de paiement partiel.

## Décision V1 sur l’impression

Le backend ne génère pas de fichier PDF dans cette phase.

Il retourne les données structurées de la facture.

Le frontend utilise ces données pour afficher une page imprimable.

## Dépendances avec les autres modules

| Module      | Utilisation par Invoice                                               |
| ----------- | --------------------------------------------------------------------- |
| Reservation | Vérifier la réservation et récupérer les dates, prix et statut        |
| Client      | Récupérer ou figer les informations client                            |
| Room        | Récupérer ou figer le numéro de chambre et les informations de séjour |
| Report      | Consommera plus tard les données Invoice pour le chiffre d’affaires   |

## Règle d’architecture

Le module Invoice ne doit jamais lire directement les bases de données suivantes :

```text
db_reservation
db_client
db_room
```

Les communications doivent passer par des APIs REST ou être simulées temporairement pendant le développement.

## Vocabulaire métier

| Terme technique | Terme affiché     |
| --------------- | ----------------- |
| Invoice         | Facture           |
| Invoice number  | Numéro de facture |
| Invoice status  | Statut de facture |
| Reservation     | Réservation       |
| Client          | Client            |
| Payment         | Paiement          |
| Refund          | Remboursement     |
| Subtotal amount | Montant HT        |
| Tax amount      | Taxe              |
| Total amount    | Montant TTC       |

---

# 2. Enums métier Invoice

## InvoiceStatus

```text
DRAFT
ISSUED
PAID
CANCELLED
REFUNDED
```

## Signification des statuts

| Valeur API | Libellé UI | Description                           |
| ---------- | ---------- | ------------------------------------- |
| DRAFT      | Brouillon  | Facture générée mais pas encore émise |
| ISSUED     | Émise      | Facture validée et prête à être payée |
| PAID       | Payée      | Facture totalement payée              |
| CANCELLED  | Annulée    | Facture annulée avec motif            |
| REFUNDED   | Remboursée | Facture payée puis remboursée         |

## PaymentMethod

```text
CASH
CARD
BANK_TRANSFER
OTHER
```

## Libellés PaymentMethod côté frontend

| Valeur API    | Libellé UI        |
| ------------- | ----------------- |
| CASH          | Espèces           |
| CARD          | Carte bancaire    |
| BANK_TRANSFER | Virement bancaire |
| OTHER         | Autre             |

## InvoiceLineType

```text
ROOM_STAY
EXTRA_SERVICE
DISCOUNT
```

## Libellés InvoiceLineType côté frontend

| Valeur API    | Libellé UI             | Description                                      |
| ------------- | ---------------------- | ------------------------------------------------ |
| ROOM_STAY     | Séjour                 | Ligne principale liée aux nuits réservées        |
| EXTRA_SERVICE | Service supplémentaire | Ligne ajoutée plus tard pour un service hôtelier |
| DISCOUNT      | Remise                 | Réduction appliquée à la facture                 |

## Transition de statut autorisée

```text
DRAFT -> ISSUED
DRAFT -> CANCELLED

ISSUED -> PAID
ISSUED -> CANCELLED

PAID -> REFUNDED
```

## Transitions interdites

```text
PAID -> CANCELLED
PAID -> DRAFT
CANCELLED -> PAID
CANCELLED -> ISSUED
REFUNDED -> PAID
REFUNDED -> ISSUED
REFUNDED -> DRAFT
```

## Couleurs recommandées côté frontend

| Statut    | Couleur UI recommandée |
| --------- | ---------------------- |
| DRAFT     | Gris                   |
| ISSUED    | Bleu                   |
| PAID      | Vert                   |
| CANCELLED | Rouge                  |
| REFUNDED  | Violet                 |

---

# 3. DTOs du module Invoice

## GenerateInvoiceFromReservationRequest

Utilisé par :

```text
POST /api/invoices/reservation/{reservationId}
```

Exemple :

```json
{
    "taxRate": 10.0,
    "notes": "Facture générée après check-out"
}
```

## Règles de validation GenerateInvoiceFromReservationRequest

| Champ   | Obligatoire | Règle                 |
| ------- | ----------- | --------------------- |
| taxRate | Oui         | Supérieur ou égal à 0 |
| notes   | Non         | Texte libre           |

## IssueInvoiceRequest

Utilisé par :

```text
PATCH /api/invoices/{id}/issue
```

Exemple :

```json
{
    "issueDate": "2026-06-18"
}
```

## Règles de validation IssueInvoiceRequest

| Champ     | Obligatoire | Règle                         |
| --------- | ----------- | ----------------------------- |
| issueDate | Non         | Date ISO au format YYYY-MM-DD |

Si `issueDate` est absent, le backend utilise la date du jour.

## PayInvoiceRequest

Utilisé par :

```text
PATCH /api/invoices/{id}/pay
```

Exemple :

```json
{
    "paymentMethod": "CASH",
    "paymentReference": "CASH-RECEPTION-001",
    "paidAt": "2026-06-18T15:30:00"
}
```

## Règles de validation PayInvoiceRequest

| Champ            | Obligatoire | Règle                   |
| ---------------- | ----------- | ----------------------- |
| paymentMethod    | Oui         | Valeur de PaymentMethod |
| paymentReference | Non         | Texte libre             |
| paidAt           | Non         | Date et heure ISO       |

Si `paidAt` est absent, le backend utilise la date et l’heure courantes.

## CancelInvoiceRequest

Utilisé par :

```text
PATCH /api/invoices/{id}/cancel
```

Exemple :

```json
{
    "reason": "Erreur de génération de facture"
}
```

## Règles de validation CancelInvoiceRequest

| Champ  | Obligatoire | Règle    |
| ------ | ----------- | -------- |
| reason | Oui         | Non vide |

## RefundInvoiceRequest

Utilisé par :

```text
PATCH /api/invoices/{id}/refund
```

Exemple :

```json
{
    "reason": "Remboursement demandé par le client",
    "paymentReference": "REFUND-2026-0001",
    "refundedAt": "2026-06-18T16:00:00"
}
```

## Règles de validation RefundInvoiceRequest

| Champ            | Obligatoire | Règle             |
| ---------------- | ----------- | ----------------- |
| reason           | Oui         | Non vide          |
| paymentReference | Non         | Texte libre       |
| refundedAt       | Non         | Date et heure ISO |

Si `refundedAt` est absent, le backend utilise la date et l’heure courantes.

## InvoiceLineResponse

```json
{
    "id": 1,
    "type": "ROOM_STAY",
    "description": "Séjour chambre 204 - 3 nuits",
    "quantity": 3,
    "unitPrice": 650.0,
    "lineTotal": 1950.0
}
```

## InvoiceResponse

```json
{
    "id": 1,
    "invoiceNumber": "INV-2026-000001",
    "reservationId": 15,
    "clientId": 8,
    "clientFullName": "Ali Benali",
    "roomId": 4,
    "roomNumber": "204",
    "checkInDate": "2026-06-15",
    "checkOutDate": "2026-06-18",
    "nights": 3,
    "subtotalAmount": 1950.0,
    "taxRate": 10.0,
    "taxAmount": 195.0,
    "totalAmount": 2145.0,
    "status": "ISSUED",
    "paymentMethod": null,
    "paymentReference": null,
    "notes": "Facture générée après check-out",
    "cancellationReason": null,
    "refundReason": null,
    "issuedAt": "2026-06-18T10:30:00",
    "paidAt": null,
    "cancelledAt": null,
    "refundedAt": null,
    "createdAt": "2026-06-18T10:00:00",
    "updatedAt": "2026-06-18T10:30:00",
    "lines": [
        {
            "id": 1,
            "type": "ROOM_STAY",
            "description": "Séjour chambre 204 - 3 nuits",
            "quantity": 3,
            "unitPrice": 650.0,
            "lineTotal": 1950.0
        }
    ]
}
```

## External ReservationInvoiceSourceResponse

DTO minimal attendu depuis `reservation-service` ou simulé temporairement.

```json
{
    "reservationId": 15,
    "reservationStatus": "CHECKED_OUT",
    "clientId": 8,
    "clientFullName": "Ali Benali",
    "roomId": 4,
    "roomNumber": "204",
    "checkInDate": "2026-06-15",
    "checkOutDate": "2026-06-18",
    "nights": 3,
    "pricePerNight": 650.0
}
```

## Décisions de nommage

| Français               | API                |
| ---------------------- | ------------------ |
| numéro de facture      | invoiceNumber      |
| réservation            | reservationId      |
| client                 | clientId           |
| nom du client          | clientFullName     |
| chambre                | roomId             |
| numéro de chambre      | roomNumber         |
| date d’arrivée         | checkInDate        |
| date de départ         | checkOutDate       |
| nombre de nuits        | nights             |
| montant HT             | subtotalAmount     |
| taux de taxe           | taxRate            |
| montant taxe           | taxAmount          |
| montant TTC            | totalAmount        |
| statut                 | status             |
| méthode de paiement    | paymentMethod      |
| référence de paiement  | paymentReference   |
| motif d’annulation     | cancellationReason |
| motif de remboursement | refundReason       |

---

# 4. Endpoints REST Invoice

## Base URL frontend

```text
http://localhost:8080/api/invoices
```

## Endpoints retenus

| Méthode | Endpoint                                  | Description                                |
| ------- | ----------------------------------------- | ------------------------------------------ |
| POST    | /api/invoices/reservation/{reservationId} | Générer une facture depuis une réservation |
| GET     | /api/invoices                             | Lister et filtrer les factures             |
| GET     | /api/invoices/{id}                        | Consulter le détail d’une facture          |
| GET     | /api/invoices/number/{number}             | Rechercher une facture par numéro          |
| GET     | /api/invoices/client/{clientId}           | Consulter les factures d’un client         |
| GET     | /api/invoices/reservation/{reservationId} | Consulter la facture d’une réservation     |
| PATCH   | /api/invoices/{id}/issue                  | Émettre une facture                        |
| PATCH   | /api/invoices/{id}/pay                    | Marquer une facture comme payée            |
| PATCH   | /api/invoices/{id}/cancel                 | Annuler une facture                        |
| PATCH   | /api/invoices/{id}/refund                 | Rembourser une facture                     |
| GET     | /api/invoices/ping                        | Tester techniquement le service            |

## Query params de liste

Endpoint :

```text
GET /api/invoices
```

Query params disponibles :

| Paramètre     | Exemple         | Description                     |
| ------------- | --------------- | ------------------------------- |
| number        | INV-2026-000001 | Recherche par numéro de facture |
| status        | PAID            | Filtre par statut               |
| clientId      | 8               | Filtre par client               |
| reservationId | 15              | Filtre par réservation          |
| from          | 2026-06-01      | Début de période                |
| to            | 2026-06-30      | Fin de période                  |
| page          | 0               | Numéro de page                  |
| size          | 20              | Taille de page                  |
| sort          | createdAt,desc  | Tri                             |

Exemple :

```text
GET /api/invoices?status=PAID&clientId=8&from=2026-06-01&to=2026-06-30&page=0&size=20&sort=createdAt,desc
```

## Codes HTTP attendus

| Cas                                        | Code |
| ------------------------------------------ | ---- |
| Lecture réussie                            | 200  |
| Action métier réussie                      | 200  |
| Création réussie                           | 201  |
| Données invalides                          | 400  |
| Facture introuvable                        | 404  |
| Réservation introuvable                    | 404  |
| Facture déjà existante pour la réservation | 409  |
| Transition de statut interdite             | 409  |
| Facture déjà payée                         | 409  |
| Erreur serveur                             | 500  |

## Format d’erreur standard

Erreur simple :

```json
{
    "timestamp": "2026-06-18T15:00:00",
    "status": 404,
    "error": "NOT_FOUND",
    "message": "Invoice not found with id: 1",
    "path": "/api/invoices/1"
}
```

Erreur de validation :

```json
{
    "timestamp": "2026-06-18T15:00:00",
    "status": 400,
    "error": "VALIDATION_ERROR",
    "message": "Validation failed",
    "path": "/api/invoices/1/pay",
    "fieldErrors": {
        "paymentMethod": "Payment method is required"
    }
}
```

Erreur de conflit :

```json
{
    "timestamp": "2026-06-18T15:00:00",
    "status": 409,
    "error": "CONFLICT",
    "message": "An active invoice already exists for reservation id: 15",
    "path": "/api/invoices/reservation/15"
}
```

## Sécurité temporaire

Dans cette phase, les routes Invoice peuvent être temporairement publiques pour accélérer la démonstration.

La sécurisation par JWT et rôles sera reprise plus tard.

## Rôles futurs recommandés

| Action                            | Rôles futurs                 |
| --------------------------------- | ---------------------------- |
| Lister les factures               | ADMIN, MANAGER, RECEPTIONIST |
| Générer une facture               | ADMIN, MANAGER, RECEPTIONIST |
| Émettre une facture               | ADMIN, MANAGER, RECEPTIONIST |
| Marquer comme payée               | ADMIN, MANAGER, RECEPTIONIST |
| Annuler une facture               | ADMIN, MANAGER               |
| Rembourser une facture            | ADMIN, MANAGER               |
| Consulter les rapports financiers | ADMIN, MANAGER               |

---

# 5. Règles métier du module Invoice

## Règles de génération

- Une facture doit être générée à partir d’une réservation existante.
- Une facture doit être liée à un `reservationId`.
- Une facture doit être liée à un `clientId`.
- Une facture doit conserver le nom du client au moment de sa génération.
- Une facture doit conserver le numéro de chambre au moment de sa génération.
- Une facture doit conserver le prix par nuit au moment de sa génération.
- Une facture doit conserver le nombre de nuits au moment de sa génération.
- Une facture doit conserver les dates de séjour au moment de sa génération.
- Une facture générée commence avec le statut `DRAFT`.
- Le numéro de facture est généré par le backend.
- Le numéro de facture doit être unique.
- Une réservation ne peut avoir qu’une seule facture active.

## Facture active

Une facture est considérée active si son statut est :

```text
DRAFT
ISSUED
PAID
```

Une facture n’est plus considérée active si son statut est :

```text
CANCELLED
REFUNDED
```

## Règles liées à la réservation

Dans la V1, une facture peut être générée uniquement pour une réservation terminée.

Statut attendu côté Reservation :

```text
CHECKED_OUT
```

Si `reservation-service` n’est pas encore terminé, cette règle peut être simulée temporairement avec un DTO externe minimal.

## Règles de calcul

Le nombre de nuits doit être calculé à partir de :

```text
checkOutDate - checkInDate
```

Le nombre de nuits doit être strictement supérieur à 0.

Le montant HT est calculé ainsi :

```text
subtotalAmount = nights * pricePerNight
```

Le montant de taxe est calculé ainsi :

```text
taxAmount = subtotalAmount * taxRate / 100
```

Le montant TTC est calculé ainsi :

```text
totalAmount = subtotalAmount + taxAmount
```

Le taux de taxe doit être supérieur ou égal à 0.

Le montant total doit être supérieur ou égal à 0.

## Règles d’émission

- Seule une facture `DRAFT` peut être émise.
- Une facture émise passe au statut `ISSUED`.
- La date d’émission doit être enregistrée dans `issuedAt`.
- Une facture `ISSUED` ne doit plus modifier les informations de réservation figées.
- Une facture `ISSUED` peut être payée.
- Une facture `ISSUED` peut être annulée.

Transition autorisée :

```text
DRAFT -> ISSUED
```

## Règles de paiement

- Seule une facture `ISSUED` peut être payée.
- Une facture payée passe au statut `PAID`.
- La méthode de paiement est obligatoire.
- La date de paiement doit être enregistrée dans `paidAt`.
- Une facture `PAID` ne peut pas être modifiée.
- Une facture `PAID` ne peut pas être supprimée.
- Une facture `PAID` ne peut pas être annulée.
- Une facture `PAID` peut être remboursée.

Transition autorisée :

```text
ISSUED -> PAID
```

## Règles d’annulation

- Une facture `DRAFT` peut être annulée.
- Une facture `ISSUED` peut être annulée.
- Une facture `PAID` ne peut pas être annulée.
- Une facture `REFUNDED` ne peut pas être annulée.
- Le motif d’annulation est obligatoire.
- Le motif d’annulation doit être conservé.
- La date d’annulation doit être enregistrée dans `cancelledAt`.

Transitions autorisées :

```text
DRAFT -> CANCELLED
ISSUED -> CANCELLED
```

## Règles de remboursement

- Seule une facture `PAID` peut être remboursée.
- Le motif de remboursement est obligatoire.
- Une facture remboursée passe au statut `REFUNDED`.
- La date de remboursement doit être enregistrée dans `refundedAt`.
- Une facture `REFUNDED` ne peut plus changer de statut.

Transition autorisée :

```text
PAID -> REFUNDED
```

## Règles de modification

Dans la V1, il n’y a pas d’endpoint `PUT` pour modifier une facture.

Les modifications métier se font uniquement par actions :

```text
issue
pay
cancel
refund
```

Pourquoi :

- une facture doit rester traçable ;
- une facture payée ne doit jamais être modifiée ;
- les données financières doivent rester stables ;
- les changements doivent passer par des transitions explicites.

## Règles de suppression

Dans la V1, il n’y a pas d’endpoint `DELETE` pour supprimer une facture.

Une facture incorrecte doit être annulée avec un motif.

Pourquoi :

- conserver l’historique financier ;
- éviter la perte de données ;
- garder une trace des erreurs de facturation.

## Règles d’intégration inter-services

Le module Invoice peut appeler :

```text
reservation-service
client-service
room-service
```

Le module Invoice ne doit jamais lire directement :

```text
db_reservation
db_client
db_room
```

Les informations récupérées depuis les autres services doivent être copiées dans la facture pour conserver un snapshot.

## Snapshot obligatoire

Une facture doit conserver au minimum :

- `clientId` ;
- `clientFullName` ;
- `reservationId` ;
- `roomId` ;
- `roomNumber` ;
- `checkInDate` ;
- `checkOutDate` ;
- `nights` ;
- `pricePerNight` ;
- `subtotalAmount` ;
- `taxRate` ;
- `taxAmount` ;
- `totalAmount`.

## Conflits métier

| Cas                                               | Code attendu |
| ------------------------------------------------- | ------------ |
| Facture introuvable                               | 404          |
| Réservation introuvable                           | 404          |
| Réservation non terminée                          | 409          |
| Facture active déjà existante pour la réservation | 409          |
| Facture déjà payée                                | 409          |
| Transition de statut interdite                    | 409          |
| Remboursement d’une facture non payée             | 409          |
| Annulation sans motif                             | 400          |
| Paiement sans méthode de paiement                 | 400          |
| Taxe invalide                                     | 400          |

## Exemples de transitions valides

```text
DRAFT -> ISSUED -> PAID -> REFUNDED
```

```text
DRAFT -> CANCELLED
```

```text
DRAFT -> ISSUED -> CANCELLED
```

## Exemples de transitions invalides

```text
PAID -> CANCELLED
CANCELLED -> PAID
REFUNDED -> ISSUED
DRAFT -> PAID
ISSUED -> REFUNDED
```

---

# 6. Acceptance Criteria global

- Le périmètre du module est défini.
- Les fonctionnalités hors périmètre sont clairement listées.
- Les dépendances avec Reservation, Client et Room sont identifiées.
- Les enums sont stables.
- Les DTOs sont documentés avec exemples JSON.
- Les endpoints sont documentés avec méthodes HTTP.
- Les règles métier principales sont connues avant le code.
- Les règles de génération sont documentées.
- Les règles de calcul sont documentées.
- Les transitions de statut sont documentées.
- Les règles de paiement sont documentées.
- Les règles d’annulation sont documentées.
- Les règles de remboursement sont documentées.
- Le backend sait quelles validations implémenter.
- Le frontend sait quels messages afficher.
- La suppression physique est exclue de la V1.
- Le backend et le frontend peuvent commencer sans ambiguïté.
