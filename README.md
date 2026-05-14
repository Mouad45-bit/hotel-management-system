# Hotel Management System

Système de gestion d'hôtel basé sur une architecture microservices.

## Stack technique

- Java 17
- Spring Boot
- Spring Cloud Config
- Eureka Server
- Spring Cloud Gateway
- MariaDB
- Docker Compose
- Jira Scrum
- GitHub

## Branch strategy

- main : version stable
- develop : intégration des stories terminées
- feature/HMS-xxx-description : développement d'une story Jira

## Sprint 1

Objectif : construire le socle infrastructure microservices.

Stories principales :
- HMS-4 : Mettre en place le config-server
- HMS-5 : Mettre en place le eureka-server
- HMS-58 : Ajouter un réseau Docker commun
- HMS-66 : Ajouter les bases de données par service
