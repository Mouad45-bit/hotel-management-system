# Room API Contract

## Objectif

Ce dossier contient le contrat commun backend/frontend pour le module Room.

Il doit être validé avant le développement parallèle du backend et du frontend.

## Stories couvertes

| Story | Fichier |
|---|---|
| HMS-119 | room-scope.md |
| HMS-120 | room-enums.md |
| HMS-121 | room-dtos.md |
| HMS-122 | room-endpoints.md |
| HMS-123 | room-business-rules.md |

## Décisions principales

- Le nom technique du module est Room.
- Le nom affiché dans l’interface est Chambres.
- L’API utilise `/api/rooms`.
- Les valeurs d’enums sont en anglais.
- Les libellés UI sont en français.
- La sécurité JWT est temporairement exclue de cette phase.
- Les routes seront sécurisées plus tard dans l’epic sécurité.

## Utilisation par le backend

Le backend doit implémenter les DTOs, endpoints et règles métier décrits dans ce dossier.

## Utilisation par le frontend

Le frontend doit créer ses types TypeScript, mocks et appels API à partir de ce contrat.
