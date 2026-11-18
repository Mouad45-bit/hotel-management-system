# Définir le périmètre fonctionnel du module Room

## Objectif

Définir clairement ce que le module Room doit couvrir dans la première version démontrable.

Le module Room permet de gérer l’inventaire des chambres de l’hôtel.

## Fonctionnalités incluses dans la V1

- Créer une chambre
- Consulter la liste des chambres
- Consulter le détail d’une chambre
- Modifier une chambre
- Supprimer ou désactiver une chambre
- Changer le statut d’une chambre
- Filtrer les chambres par type, statut, étage et capacité
- Afficher des statistiques simples sur les chambres

## Fonctionnalités exclues temporairement

- Réservation réelle
- Check-in
- Check-out
- Paiement
- Sécurité JWT complète
- Permissions par rôle
- Historique détaillé des changements

## Décision temporaire sur la sécurité

Pour des raisons de délai, les endpoints Room seront temporairement accessibles sans authentification complète.

La sécurité sera reprise plus tard dans l’epic dédié :

HMS-DEBT-SEC-01 — Rebrancher Room Service sur la sécurité JWT.

## Vocabulaire métier

| Terme technique | Terme affiché |
|---|---|
| Room | Chambre |
| Room type | Type de chambre |
| Room status | Statut de chambre |
| Floor | Étage |
| Capacity | Capacité |
| Price per night | Prix par nuit |

## Acceptance Criteria

- Le périmètre V1 est documenté.
- Les fonctionnalités hors périmètre sont clairement listées.
- L’équipe backend et frontend comprend le même objectif.
- La dette technique sécurité est connue et sera reprise plus tard.
