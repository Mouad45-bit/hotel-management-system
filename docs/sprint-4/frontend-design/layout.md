Layout global
=======================

Objectif
--------

Définir la structure générale de l'interface frontend.

Inspiration
-----------

Le layout reprend la logique du projet existant :

-   sidebar verticale fixe à gauche
-   logo ou nom de l'application en haut de la sidebar
-   menu principal sous le logo
-   contenu principal sur fond clair
-   topbar avec titre de page et utilisateur
-   tableaux et cards dans des blocs blancs

Layout retenu
-------------

L'application utilisera un layout de type dashboard.

Structure :

```
+------------------------------------------------------+
| Sidebar | Topbar                                     |
|         |--------------------------------------------|
|         | Page content                               |
|         |                                            |
|         | Cards / Tables / Forms / Filters           |
+------------------------------------------------------+
```

Sidebar
-------

La sidebar contient la navigation principale.

Menus prévus :

```
Dashboard
Chambres
Clients
Réservations
Factures
Housekeeping
Personnel
Rapports
Paramètres
```

Pour la première version, seul le menu Chambres sera réellement utilisé.

Les autres menus peuvent être affichés comme éléments désactivés ou futurs modules.

Topbar
------

La topbar contient :

```
titre de la page
description courte
zone utilisateur temporaire
bouton d’action principal selon la page
```

Exemple pour la page Chambres :

```
Titre : Chambres
Description : Gestion de l’inventaire des chambres de l’hôtel
Action : Ajouter une chambre
```

Zone de contenu
---------------

La page Chambres doit contenir :

```
cards statistiques
zone de filtres
tableau des chambres
actions rapides
```

Responsive
----------

Pour la première version :

-   desktop prioritaire
-   tablette acceptable
-   mobile non prioritaire pour la démo

Règle
-----

Toutes les pages futures doivent passer par le même composant AppLayout.
