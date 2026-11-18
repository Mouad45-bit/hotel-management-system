Définir les règles métier du module Room
=======================================

Objectif
----------------

Définir les règles métier minimales que le backend devra appliquer.

Règles de création
----------------

- Le numéro de chambre est obligatoire.
- Le numéro de chambre doit être unique.
- L’étage est obligatoire.
- La capacité doit être supérieure à 0.
- Le prix par nuit doit être supérieur ou égal à 0.
- Le type est obligatoire.
- Le statut est obligatoire.

Règles de modification
----------------

- Une chambre existante peut être modifiée.
- Si le numéro est modifié, il doit rester unique.
- Une chambre inexistante retourne 404.
- Une donnée invalide retourne 400.

Règles de suppression
----------------

La suppression sera logique.

Cela signifie :

```text
active = false
```

La chambre reste en base de données, mais elle n'apparaît plus dans la liste principale.

Règles de statut
----------------

-   AVAILABLE signifie que la chambre peut être proposée à la réservation plus tard.
-   RESERVED sera utilisé plus tard par le module réservation.
-   OCCUPIED sera utilisé plus tard après check-in.
-   CLEANING signifie que la chambre est temporairement indisponible.
-   MAINTENANCE signifie que la chambre est indisponible pour raison technique.
-   OUT_OF_SERVICE signifie que la chambre est retirée de l'exploitation.

Règles de disponibilité
-----------------------

Dans cette version, une chambre est considérée disponible uniquement si :

```
status = AVAILABLE
active = true
```

Conflits métier
---------------

| Cas | Code attendu |
| --- | --- |
| Numéro déjà utilisé | 409 |
| Chambre introuvable | 404 |
| Statut invalide | 400 |
| Capacité invalide | 400 |
| Prix invalide | 400 |

Acceptance Criteria
-------------------

-   Les règles métier sont documentées.
-   Le backend sait quelles validations implémenter.
-   Le frontend sait quels messages afficher.
-   La suppression logique est validée.
