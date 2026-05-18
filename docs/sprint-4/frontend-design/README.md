Frontend Design Foundation
==========================

Objectif
--------

Ce dossier définit le socle visuel et ergonomique du frontend HMS.

Il sert de référence pour construire une interface claire, cohérente, professionnelle et présentable à l'encadrant.

Stories couvertes
-----------------

| Story | Fichier |
|---|---|
| HMS-125 | visual-identity.md |
| HMS-125 | layout.md |
| HMS-125 | components.md |
| HMS-125 | room-module-wireframe.md |
| HMS-125 | tailwind-ui-stack.md |

Inspiration design
------------------

Le design global de HMS s'inspire du projet de gestion de projets déjà réalisé.

Les éléments visuels à reprendre sont :

- interface dashboard claire
- sidebar fixe à gauche
- topbar sobre
- fond gris très clair
- cartes blanches avec bordures discrètes
- tableaux propres et lisibles
- boutons principaux en couleur brun/marron
- badges colorés pour les statuts
- modals simples
- formulaires compacts
- espacement généreux
- design professionnel et non surchargé

Stack UI retenu
---------------

Le frontend utilisera un stack gratuit et officiel basé sur :

- Tailwind CSS
- Headless UI
- Heroicons
- composants HMS personnalisés

Headless UI sera utilisé pour les composants interactifs accessibles comme les dialogs, menus et listbox.

Heroicons sera utilisé pour les icônes.

Les composants visuels propres au projet seront développés dans `components/hms`.

Décisions principales
---------------------

- Le frontend utilise Next.js.
- Le routing utilise App Router.
- Le style utilise Tailwind CSS.
- Le design s'inspire de l'ancien projet fourni en captures.
- Le projet n'utilise pas Catalyst.
- Les composants interactifs utilisent Headless UI si nécessaire.
- Les icônes utilisent Heroicons.
- Le module affiché dans l'interface est Chambres.
- Le module technique reste Room.
- La première démonstration se concentre sur la gestion des chambres.

Pages prévues pour la première démonstration
--------------------------------------------

- Dashboard général
- Liste des chambres
- Création d'une chambre
- Modification d'une chambre
- Détail rapide d'une chambre

Composants principaux
---------------------

- Sidebar
- Topbar
- AppLayout
- HmsCard
- HmsButton
- HmsBadge
- RoomStatsCards
- RoomTable
- RoomFilters
- RoomStatusBadge
- RoomForm
- DeleteRoomDialog
- Notifications utilisateur

Règle
-----

Toute nouvelle page frontend doit respecter cette base visuelle.
