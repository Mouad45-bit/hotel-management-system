Wireframe du module Room
==================================

Objectif
--------

Définir la structure visuelle attendue pour la page Chambres.

Inspiration
-----------

Le module Room doit reprendre l'organisation visuelle du projet existant :

-   sidebar à gauche
-   topbar en haut
-   contenu principal clair
-   cards statistiques en haut
-   filtres avant le tableau
-   tableau central
-   actions à droite
-   boutons sobres
-   badges colorés

Page Chambres
-------------

Route frontend :

```
/rooms
```

Structure de la page
--------------------

```
+------------------------------------------------------+
| Topbar                                               |
| Chambres                              Ajouter chambre |
| Gestion de l’inventaire des chambres                 |
+------------------------------------------------------+

+------------+------------+------------+------------+
| Total      | Disponibles| Occupées   | Maintenance|
+------------+------------+------------+------------+

+------------------------------------------------------+
| Filtres                                              |
| Numéro | Type | Statut | Étage | Capacité | Reset   |
+------------------------------------------------------+

+------------------------------------------------------+
| Tableau des chambres                                 |
| Numéro | Type | Étage | Capacité | Prix | Statut  |
| Actions : Voir | Modifier | Supprimer                |
+------------------------------------------------------+
```

Formulaire Ajouter / Modifier
-----------------------------

Le formulaire sera affiché dans un Dialog ou un Drawer.

Champs :

```
number
floor
type
pricePerNight
capacity
status
description
```

Détail rapide
-------------

Le détail rapide d'une chambre peut être affiché plus tard sous forme de drawer ou modal.

Informations à afficher :

```
numéro
type
statut
étage
capacité
prix par nuit
description
date de création
date de modification
```

Règles UX
---------

-   Le bouton Ajouter chambre doit être visible en haut.
-   Les statuts doivent être colorés.
-   Les filtres doivent être au-dessus du tableau.
-   Le tableau doit rester lisible.
-   Les actions dangereuses doivent demander confirmation.
-   Le design doit rester proche du style du projet existant.
