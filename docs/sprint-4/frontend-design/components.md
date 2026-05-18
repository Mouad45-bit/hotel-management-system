Composants frontend réutilisables
===========================================

Objectif
--------

Lister les composants nécessaires pour construire rapidement l'interface du module Room.

Les composants doivent s'appuyer autant que possible sur Catalyst UI Kit for Tailwind CSS afin d'obtenir une interface professionnelle rapidement.

Règle d'utilisation de Catalyst
-------------------------------

Catalyst fournit des composants React + Tailwind prêts à être copiés dans le projet.

Dans HMS, les composants Catalyst seront placés dans :

```
frontend/src/components/catalyst
```

Les composants métier HMS seront placés dans :

```
frontend/src/components/rooms
frontend/src/components/layout
```

Composants Catalyst à utiliser
------------------------------

| Besoin HMS | Composant Catalyst recommandé |
| --- | --- |
| Boutons | Button |
| Champs texte | Input |
| Sélections | Select |
| Formulaires | Fieldset, Field, Label |
| Modals | Dialog |
| Menus | Dropdown |
| Tableaux | Table |
| Badges | Badge |
| Navigation | Navbar / Sidebar selon besoin |

Composants layout HMS
---------------------

| Composant | Rôle |
| --- | --- |
| AppLayout | Structure globale de l'application |
| Sidebar | Navigation principale |
| Topbar | En-tête de page |

Composants Room
---------------

| Composant | Rôle |
| --- | --- |
| RoomStatsCards | Afficher les statistiques des chambres |
| RoomTable | Afficher la liste des chambres |
| RoomFilters | Filtrer les chambres |
| RoomStatusBadge | Afficher le statut d'une chambre |
| RoomForm | Créer ou modifier une chambre |
| DeleteRoomDialog | Confirmer la suppression d'une chambre |

Composants UI génériques
------------------------

Les composants UI génériques doivent venir en priorité de Catalyst.

Si Catalyst ne fournit pas un composant adapté, l'équipe peut créer un composant HMS personnalisé.

| Composant | Source recommandée |
| --- | --- |
| Button | Catalyst |
| Input | Catalyst |
| Select | Catalyst |
| Card | HMS personnalisé |
| Badge | Catalyst ou HMS personnalisé |
| Dialog | Catalyst |
| Toast | HMS personnalisé ou bibliothèque légère plus tard |
| Table | Catalyst |

Règles de conception
--------------------

-   Un composant doit avoir une responsabilité claire.
-   Les composants Room doivent utiliser les types définis dans `types/room.ts`.
-   Les composants ne doivent pas appeler directement l'API.
-   Les appels API doivent passer par `services/roomApi.ts`.
-   Les composants doivent rester faciles à tester et réutiliser.
-   Les composants Catalyst peuvent être adaptés visuellement pour respecter la palette HMS.
-   Les composants ne doivent pas être surchargés inutilement.

Priorité de développement
-------------------------

Ordre recommandé :

```
1. AppLayout
2. Sidebar
3. Topbar
4. RoomStatusBadge
5. RoomStatsCards
6. RoomFilters
7. RoomTable
8. RoomForm
9. DeleteRoomDialog
```
