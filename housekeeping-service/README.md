# housekeeping-service

Microservice HMS responsable des tâches de nettoyage, inspection et remise en état des chambres.

## Rôle

- Créer et suivre les tâches housekeeping.
- Assigner une tâche à un agent.
- Piloter le cycle de vie `TODO -> IN_PROGRESS -> DONE` ou `CANCELLED`.
- Exposer les vues opérationnelles par chambre, agent et date du jour.

## Architecture

Le service possède sa propre base `db_housekeeping`. Il ne lit jamais directement les bases Room, Staff ou Reservation. Les dépendances inter-services passent par des clients REST avec fallback temporaire documenté dans le code.

## Port

`8086`

## Resource path

`/api/housekeeping-tasks`

## Build local

```bash
mvn -f housekeeping-service/pom.xml clean package
```
