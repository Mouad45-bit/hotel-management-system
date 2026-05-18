Frontend Design Foundation
====================================

Objectif
--------

Ce dossier définit le socle visuel et ergonomique du frontend HMS.

Il sert de référence pour construire une interface claire, cohérente, professionnelle et présentable à l'encadrant.

Stories couvertes
-----------------

| Story | Fichier |
| --- | --- |
| HMS-125 | visual-identity.md |
| HMS-125 | layout.md |
| HMS-125 | components.md |
| HMS-125 | room-module-wireframe.md |
| HMS-125 | catalyst-ui-kit.md |

Inspiration design
------------------

Le design global de HMS s'inspire du projet de gestion de projets déjà réalisé.

Les éléments visuels à reprendre sont :

-   interface dashboard claire
-   sidebar fixe à gauche
-   topbar sobre
-   fond gris très clair
-   cartes blanches avec bordures discrètes
-   tableaux propres et lisibles
-   boutons principaux en couleur brun/marron
-   badges colorés pour les statuts
-   modals simples
-   formulaires compacts
-   espacement généreux
-   design professionnel et non surchargé

UI Kit retenu
-------------

Le frontend utilisera Catalyst UI Kit for Tailwind CSS comme base de composants.

Catalyst sera utilisé pour accélérer la création de composants professionnels tels que :

-   Button
-   Input
-   Select
-   Dialog
-   Dropdown
-   Table
-   Badge
-   Fieldset
-   Navbar
-   Sidebar si nécessaire

Décisions principales
---------------------

-   Le frontend utilise Next.js.
-   Le routing utilise App Router.
-   Le style utilise Tailwind CSS.
-   Le design s'inspire de l'ancien projet fourni en captures.
-   Les composants UI s'appuient sur Catalyst UI Kit.
-   Le module affiché dans l'interface est Chambres.
-   Le module technique reste Room.
-   La première démonstration se concentre sur la gestion des chambres.

Pages prévues pour la première démonstration
--------------------------------------------

-   Dashboard général
-   Liste des chambres
-   Création d'une chambre
-   Modification d'une chambre
-   Détail rapide d'une chambre

Composants principaux
---------------------

-   Sidebar
-   Topbar
-   AppLayout
-   RoomStatsCards
-   RoomTable
-   RoomFilters
-   RoomStatusBadge
-   RoomForm
-   DeleteRoomDialog
-   Notifications utilisateur

Règle
-----

Toute nouvelle page frontend doit respecter cette base visuelle.
