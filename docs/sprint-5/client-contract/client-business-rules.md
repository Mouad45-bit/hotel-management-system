Définir les règles métier du module Client
=======================================

Objectif
----------------

Définir les règles métier minimales que le backend devra appliquer.

Règle d'identification (critique)
----------------

Au moins un des champs suivants doit être fourni :

- email
- phone
- cin
- passportNumber

Si aucun n'est fourni, le backend retourne 400 avec le message :

```
"At least one identification field is required (email, phone, cin or passportNumber)"
```

Le frontend valide également cette règle côté client via Zod.

Règles de création
----------------

- Le prénom est obligatoire.
- Le nom de famille est obligatoire.
- L'email doit avoir un format valide s'il est fourni.
- L'email doit être unique dans la base.
- Le CIN doit être unique dans la base s'il est fourni.
- Le numéro de passeport doit être unique dans la base s'il est fourni.
- La date de naissance doit être dans le passé.

Règles de modification
----------------

- Un client existant peut être modifié.
- Si l'email est modifié, il doit rester unique (hors client courant).
- Si le CIN est modifié, il doit rester unique (hors client courant).
- Si le passeport est modifié, il doit rester unique (hors client courant).
- Un client inexistant retourne 404.
- Une donnée invalide retourne 400.

Règles de suppression
----------------

La suppression est logique uniquement.

```text
active = false
```

Le client reste en base de données, mais il n'apparaît plus dans la liste principale.

Règle de disponibilité pour les réservations
--------------------------------------------

Un client ne peut être associé à une nouvelle réservation que si :

```
active = true
```

Le `reservation-service` doit vérifier cette condition avant de créer une réservation.

Conflits métier
---------------

| Cas | Code attendu |
| --- | --- |
| Email déjà utilisé | 409 |
| CIN déjà utilisé | 409 |
| Passeport déjà utilisé | 409 |
| Aucune identification fournie | 400 |
| Client introuvable | 404 |
| Date de naissance invalide | 400 |
| Email invalide | 400 |

Acceptance Criteria
-------------------

- Les règles métier sont documentées.
- La règle d'identification est validée backend ET frontend.
- Les contraintes d'unicité sont connues.
- Le backend sait quelles validations implémenter.
- Le frontend sait quels messages afficher.
- La suppression logique est validée.
- Le reservation-service connaît la condition d'activation.
