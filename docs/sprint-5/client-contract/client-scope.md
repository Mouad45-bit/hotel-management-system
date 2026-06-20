# Définir le périmètre fonctionnel du module Client

## Objectif

Définir clairement ce que le module Client doit couvrir dans la première version démontrable.

Le module Client permet de gérer le répertoire des clients de l'hôtel.

## Fonctionnalités incluses dans la V1

- Créer un client
- Consulter la liste des clients actifs
- Consulter la liste des clients inactifs
- Consulter le détail d'un client
- Modifier un client
- Désactiver un client (suppression logique)
- Réactiver un client
- Rechercher un client par nom, prénom, email ou CIN

## Fonctionnalités exclues temporairement

- Historique des réservations (stub vide en V1)
- Historique des factures
- Import/export CSV
- Photo de profil
- Sécurité JWT complète
- Permissions par rôle

## Décision temporaire sur la sécurité

Pour des raisons de délai, les endpoints Client seront temporairement accessibles sans authentification complète.

La sécurité sera reprise plus tard dans l'epic dédié :

HMS-DEBT-SEC-02 — Rebrancher Client Service sur la sécurité JWT.

## Vocabulaire métier

| Terme technique | Terme affiché |
|---|---|
| Client | Client |
| First name | Prénom |
| Last name | Nom |
| Email | Email |
| Phone | Téléphone |
| CIN | CIN |
| Passport number | Numéro de passeport |
| Nationality | Nationalité |
| Address | Adresse |
| Birth date | Date de naissance |
| Active | Actif |

## Acceptance Criteria

- Le périmètre V1 est documenté.
- Les fonctionnalités hors périmètre sont clairement listées.
- L'équipe backend et frontend comprend le même objectif.
- La règle "au moins 1 identification" est validée des deux côtés.
- La dette technique sécurité est connue et sera reprise plus tard.
