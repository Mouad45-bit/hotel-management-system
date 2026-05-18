Utilisation de Catalyst UI Kit
========================================

Objectif
--------

Définir comment Catalyst UI Kit for Tailwind CSS sera utilisé dans le frontend HMS.

Pourquoi Catalyst ?
-------------------

Catalyst permet d'utiliser des composants React + Tailwind CSS professionnels et cohérents.

Cela permet de gagner du temps sur :

-   les boutons
-   les formulaires
-   les tableaux
-   les dialogs
-   les dropdowns
-   les badges
-   les composants de navigation

Décision
--------

Le projet HMS utilisera Catalyst comme base UI.

Catalyst ne remplacera pas les composants métier HMS.

Il servira de base pour construire les composants spécifiques au module Room.

Installation prévue
-------------------

Catalyst doit être récupéré depuis le compte Tailwind Plus de l'équipe.

Après téléchargement du fichier ZIP Catalyst, copier les composants TypeScript dans :

```
frontend/src/components/catalyst
```

Dépendances Catalyst
--------------------

Les dépendances à installer côté frontend sont :

```
@headlessui/react
motion
clsx
```

Commande prévue :

```
npm install @headlessui/react motion clsx
```

Organisation recommandée
------------------------

```
frontend/src/components/catalyst
frontend/src/components/layout
frontend/src/components/rooms
```

Règle d'import
--------------

Les composants Catalyst doivent être importés depuis :

```
@/components/catalyst/button
@/components/catalyst/input
@/components/catalyst/select
@/components/catalyst/dialog
@/components/catalyst/table
```

Exemple d'utilisation attendue
------------------------------

```
import { Button } from "@/components/catalyst/button"
import { Input } from "@/components/catalyst/input"
import { Dialog } from "@/components/catalyst/dialog"
```

Adaptation visuelle
-------------------

Les composants Catalyst peuvent être adaptés pour respecter la palette HMS :

-   brun/marron pour les actions principales
-   gris clair pour les fonds
-   blanc pour les cards
-   badges colorés pour les statuts Room

Règles
------

-   Ne pas modifier massivement Catalyst dès le départ.
-   Commencer avec les composants tels qu'ils sont fournis.
-   Adapter uniquement les couleurs nécessaires à l'identité HMS.
-   Garder les composants Catalyst séparés des composants métier Room.
-   Ne pas créer un composant custom si Catalyst fournit déjà une base propre.

Limite
------

Catalyst est un kit de composants copié dans le projet.

Ce n'est pas une dépendance UI installée comme une bibliothèque classique.

Les composants deviennent donc du code local du projet HMS.
