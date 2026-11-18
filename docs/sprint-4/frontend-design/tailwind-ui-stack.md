Stack UI officiel gratuit Tailwind Labs
======================================

Objectif
--------

Définir le stack UI gratuit, officiel et maintenable utilisé dans le frontend HMS.

Décision
--------

Le projet HMS n'utilise pas Catalyst UI Kit, car Catalyst fait partie de Tailwind Plus et nécessite une licence payante.

Le projet HMS utilise à la place un stack officiel gratuit basé sur :

- Tailwind CSS
- Headless UI
- Heroicons
- composants HMS personnalisés

Pourquoi ce choix ?
-------------------

Ce choix permet de rester sur une base :

- gratuite
- officielle
- compatible avec Tailwind CSS
- professionnelle
- maintenable
- défendable dans le rapport de projet

Stack retenu
------------

```
Next.js
TypeScript
Tailwind CSS
Headless UI
Heroicons
Zod
clsx
```

Rôle de chaque outil
--------------------

| Outil | Rôle |
| --- | --- |
| Tailwind CSS | Styling principal |
| Headless UI | Composants interactifs accessibles non stylisés |
| Heroicons | Icônes officielles de l'écosystème Tailwind |
| Zod | Validation des formulaires |
| clsx | Composition conditionnelle des classes CSS |
| Composants HMS | Cards, boutons, badges, layout et composants métier |

Organisation recommandée
------------------------

```
frontend/src/components/hms
frontend/src/components/layout
frontend/src/components/rooms
frontend/src/lib
frontend/src/services
frontend/src/types
frontend/src/schemas
```

Règle importante
----------------

Headless UI ne fournit pas le style visuel final.

Il fournit le comportement accessible des composants interactifs.

Le style HMS est donc construit avec Tailwind CSS dans nos propres composants.

Exemples :

-   Dialog Headless UI + classes Tailwind HMS
-   Menu Headless UI + classes Tailwind HMS
-   Listbox Headless UI + classes Tailwind HMS
-   Heroicons pour les icônes de navigation

Composants HMS à créer
----------------------

| Composant | Rôle |
| --- | --- |
| HmsCard | Carte dashboard |
| HmsButton | Bouton stylisé HMS |
| HmsBadge | Badge de statut |
| HmsInput | Champ de formulaire |
| HmsSelect | Select simple ou Listbox Headless UI |
| AppLayout | Layout global |
| Sidebar | Navigation principale |
| Topbar | En-tête de page |
| RoomTable | Tableau chambres |
| RoomForm | Formulaire chambres |
| DeleteRoomDialog | Confirmation avec Headless UI Dialog |

Règles
------

-   Ne pas utiliser Catalyst dans cette version.
-   Ne pas créer de dossier `components/catalyst`.
-   Utiliser Headless UI pour les composants interactifs complexes.
-   Utiliser Heroicons pour les icônes.
-   Garder les composants métier dans `components/rooms`.
-   Garder les composants UI propres au projet dans `components/hms`.
-   Garder une interface proche du style de l'ancien projet.

Limite
------

Ce stack demande un peu plus de travail qu'un UI Kit payant déjà stylisé.

Mais il reste le meilleur compromis pour HMS : gratuit, officiel, professionnel et maintenable.
