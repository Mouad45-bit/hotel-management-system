Composants frontend réutilisables
=================================

Objectif
--------

Lister les composants nécessaires pour construire rapidement l'interface du module Room.

Le projet n'utilise pas Catalyst.

Les composants seront construits avec :

- Tailwind CSS pour le style
- Headless UI pour les interactions accessibles
- Heroicons pour les icônes
- composants HMS personnalisés pour garder une identité visuelle cohérente

Règle d'utilisation du stack UI
-------------------------------

Tailwind CSS fournit le style.

Headless UI fournit le comportement des composants interactifs, mais pas leur apparence.

Heroicons fournit les icônes.

Les composants HMS personnalisés appliquent l'identité visuelle du projet.

Organisation des composants
---------------------------

```
frontend/src/components/hms
frontend/src/components/layout
frontend/src/components/rooms
```

Composants HMS génériques
-------------------------

| Composant | Rôle |
| --- | --- |
| HmsCard | Carte visuelle pour dashboard, tableaux et sections |
| HmsButton | Bouton principal, secondaire ou danger |
| HmsBadge | Badge de statut |
| HmsInput | Champ de saisie stylisé |
| HmsSelect | Select simple ou basé sur Headless UI Listbox |
| HmsDialog | Wrapper autour de Headless UI Dialog si nécessaire |

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

Utilisation de Headless UI
--------------------------

Headless UI sera utilisé uniquement lorsque le composant a besoin d'un comportement interactif accessible.

Exemples :

| Besoin HMS | Solution |
| --- | --- |
| Modal de suppression | Headless UI Dialog |
| Menu utilisateur | Headless UI Menu |
| Select avancé | Headless UI Listbox |
| Transition simple | Headless UI Transition |

Utilisation de Heroicons
------------------------

Heroicons sera utilisé pour :

-   navigation sidebar
-   actions de tableau
-   boutons importants
-   états vides
-   feedback visuel léger

Règles de conception
--------------------

-   Un composant doit avoir une responsabilité claire.
-   Les composants Room doivent utiliser les types définis dans `types/room.ts`.
-   Les composants ne doivent pas appeler directement l'API.
-   Les appels API doivent passer par `services/roomApi.ts`.
-   Les composants doivent rester faciles à tester et réutiliser.
-   Les composants HMS doivent rester visuellement cohérents avec l'ancien projet.
-   Les composants interactifs complexes doivent utiliser Headless UI quand c'est utile.
-   Les composants ne doivent pas être surchargés inutilement.

Priorité de développement
-------------------------

Ordre recommandé :

```
1. AppLayout
2. Sidebar
3. Topbar
4. HmsCard
5. HmsButton
6. RoomStatusBadge
7. RoomStatsCards
8. RoomFilters
9. RoomTable
10. RoomForm
11. DeleteRoomDialog
```
