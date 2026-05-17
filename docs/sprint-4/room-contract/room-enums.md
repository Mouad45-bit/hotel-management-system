Définir les enums métier Room
=======================================

Objectif
--------

Définir les valeurs fixes utilisées par le backend et le frontend pour les types et statuts de chambres.

Les valeurs doivent rester identiques côté API, backend et frontend.

RoomType
--------

```
SINGLE
DOUBLE
TWIN
SUITE
FAMILY
DELUXE
```

RoomStatus
----------

```
AVAILABLE
RESERVED
OCCUPIED
CLEANING
MAINTENANCE
OUT_OF_SERVICE
```

Libellés affichés côté frontend
-------------------------------

| Valeur API | Libellé UI |
| --- | --- |
| AVAILABLE | Disponible |
| RESERVED | Réservée |
| OCCUPIED | Occupée |
| CLEANING | Nettoyage |
| MAINTENANCE | Maintenance |
| OUT_OF_SERVICE | Hors service |

Types affichés côté frontend
----------------------------

| Valeur API | Libellé UI |
| --- | --- |
| SINGLE | Simple |
| DOUBLE | Double |
| TWIN | Twin |
| SUITE | Suite |
| FAMILY | Familiale |
| DELUXE | Deluxe |

Couleurs recommandées des statuts
---------------------------------

| Statut | Couleur UI recommandée |
| --- | --- |
| AVAILABLE | Vert |
| RESERVED | Bleu |
| OCCUPIED | Rouge ou orange foncé |
| CLEANING | Violet |
| MAINTENANCE | Orange |
| OUT_OF_SERVICE | Gris |

Règle importante
----------------

Le frontend ne doit pas inventer d'autres valeurs.

Si une nouvelle valeur est ajoutée plus tard, elle doit d'abord être ajoutée ici, puis implémentée côté backend et frontend.

Acceptance Criteria
-------------------

-   Les enums sont documentés.
-   Les valeurs backend et frontend sont identiques.
-   Les libellés affichés sont clairs pour l'utilisateur.
