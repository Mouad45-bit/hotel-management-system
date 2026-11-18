# HMS — Frontend Design System

> **Référence officielle du design HMS**  
> **Fichier à placer à la racine du dépôt : `README-FRONTEND-DESIGN.md`**  
> Les pages `/invoices` et `/invoices/create` sont les références visuelles officielles de l’application.  
> Toute nouvelle interface HMS doit sembler avoir été conçue par le même développeur frontend, pour le même produit, au même moment.

---

## 1. Rôle de ce document

HMS est une application de gestion hôtelière destinée à la réception, au management et, à terme, aux équipes housekeeping.

Ce document définit la langue visuelle unique de l’application. Il sert de source de vérité pour créer ou restyler :

- les pages de liste ;
- les pages de création ;
- les pages de modification ;
- les pages de détail ;
- les historiques ;
- les formulaires ;
- les tableaux ;
- les sélections de ressources ;
- les aperçus financiers ou métier ;
- les popups de filtres ;
- les états vides, erreurs et chargements ;
- les composants partagés.

L’objectif n’est pas de créer un style différent pour chaque module. L’objectif est de construire une application cohérente, claire, calme, professionnelle et crédible.

> **La cohérence avec `/invoices` et `/invoices/create` est prioritaire sur toute nouvelle idée visuelle.**

---

## 2. Références visuelles officielles

### 2.1 Pages de référence

| Route | Rôle de référence |
|---|---|
| `/invoices` | Référence pour les pages de liste, statistiques, filtres, tableaux, badges, pagination et outils de page |
| `/invoices/create` | Référence pour les pages de création, sélection d’une ressource, formulaire, aperçu métier ou financier et actions finales |

### 2.2 Ce que fixe `/invoices`

La page `/invoices` définit notamment :

- la largeur de la sidebar ;
- la hauteur et la structure de la topbar ;
- la couleur du fond de contenu ;
- la hiérarchie des titres ;
- la largeur du contenu ;
- le style des cards statistiques ;
- les boutons principaux et secondaires ;
- les rayons ;
- les ombres ;
- la densité des tableaux ;
- les badges de statut ;
- les popups de filtres ;
- les espacements verticaux et horizontaux ;
- la pagination ;
- les actions icon-only dans un tableau.

### 2.3 Ce que fixe `/invoices/create`

La page `/invoices/create` définit notamment :

- le bouton retour d’une page de création ;
- la hiérarchie d’un titre de création ;
- la description métier sur une ou deux lignes ;
- le bloc de sélection d’une ressource ;
- le compteur contextuel d’éléments disponibles ;
- le comportement visuel d’une ligne sélectionnée ;
- les boutons `Sélectionner` et `Sélectionnée` ;
- les états disponibles et indisponibles ;
- la structure d’un tableau de sélection ;
- le formulaire en card ;
- l’aperçu métier ou financier ;
- la grille deux colonnes sur desktop ;
- la zone finale contenant le contexte sélectionné et les actions ;
- le flux visuel : choisir, ajuster, vérifier, confirmer.

### 2.4 Ordre de priorité en cas de doute

Lorsqu’un choix visuel doit être fait, appliquer cet ordre :

1. les captures validées de `/invoices` et `/invoices/create` ;
2. ce document ;
3. les composants partagés existants dans `frontend/src/components/hms` ;
4. les composants de layout existants dans `frontend/src/components/layout` ;
5. les tokens de `frontend/src/app/globals.css` ;
6. les conventions Next.js, Tailwind et TypeScript déjà présentes dans le projet.

Ne jamais créer une direction artistique différente pour un module isolé.

---

## 3. Contraintes techniques non négociables

### 3.1 Stack

- Next.js avec App Router ;
- TypeScript strict ;
- Tailwind CSS v4 ;
- Inter chargée avec `next/font/google` ;
- `lucide-react` pour toute nouvelle icône ;
- Headless UI autorisé uniquement pour des comportements accessibles comme `Dialog`, `Menu`, `Listbox`, `Popover` et `Transition`.

### 3.2 Respect du métier

Un changement frontend esthétique ne doit jamais modifier :

- les routes ;
- les appels API ;
- les services fetch ;
- les paramètres de requête ;
- les types TypeScript métier ;
- les schémas Zod ;
- les validations métier ;
- les calculs ;
- les règles de statut ;
- les données affichées ;
- les contrats backend ;
- les règles d’éligibilité métier.

Les composants métier ne réalisent pas directement les appels API. Les appels restent dans les services existants.

### 3.3 Interactions

- tout bouton, lien visuellement cliquable, action d’icône, onglet et ligne interactive utilise `cursor-pointer` ;
- un contrôle réellement désactivé utilise `disabled` et `cursor-not-allowed` ;
- les boutons d’icône possèdent un `aria-label` ;
- tout contrôle doit conserver un focus visible ;
- ne pas introduire de nouvel UI kit ;
- ne pas ajouter de dépendance npm sans demande explicite.

---

## 4. Intention du design HMS

HMS est un dashboard métier.

L’interface doit évoquer :

- une réception organisée ;
- une lecture rapide des informations ;
- une fiabilité financière ;
- une hiérarchie claire des actions ;
- un outil interne moderne et professionnel ;
- une gestion d’hôtel calme, précise et maîtrisée.

Le design doit rester :

- minimaliste ;
- lumineux ;
- lisible ;
- structuré ;
- dense sans être serré ;
- élégant sans devenir décoratif ;
- cohérent entre les modules ;
- adapté à une démonstration professionnelle.

### 4.1 Ce que HMS ne doit jamais devenir

Ne pas transformer HMS en :

- site marketing ;
- interface sombre ;
- dashboard avec gradients ;
- interface avec glassmorphism ;
- collection de cards fortement colorées ;
- application où chaque module a une palette différente ;
- écran avec des ombres fortes pour compenser une hiérarchie confuse ;
- interface où chaque texte est dans une card ;
- interface trop arrondie, enfantine ou générique ;
- interface décorative qui masque les données métier.

---

## 5. Identité visuelle et tokens

Les nouvelles couleurs ne doivent pas être inventées dans les composants.

Les tokens doivent rester centralisés dans :

    frontend/src/app/globals.css

### 5.1 Tokens officiels

    :root {
      --hms-primary: #191970;
      --hms-primary-hover: #15155f;
      --hms-primary-active: #111150;

      --hms-surface: #ffffff;
      --hms-page: #eceff1;

      --hms-text: #0d0907;
      --hms-text-muted: rgba(13, 9, 7, 0.62);

      --hms-border: #d8dee2;
      --hms-soft-border: #e3e7ea;

      --hms-focus: #191970;
    }

### 5.2 Palette fonctionnelle

| Usage | Valeur | Règle |
|---|---:|---|
| Action primaire / navigation active | `#191970` | Réservée à l’action principale, menu actif, profil et focus |
| Hover primaire | `#15155F` | Utilisée uniquement lors du survol d’un élément primaire |
| Fond de page | `#ECEFF1` | Surface de la zone de contenu principale |
| Surface / card / tableau / popup | `#FFFFFF` | Fond de toutes les surfaces métier |
| Texte fort | `#0D0907` | Titres, montants, données importantes |
| Texte secondaire | `rgba(13, 9, 7, 0.62)` | Dates, labels, descriptions, métadonnées |
| Bordure standard | `#D8DEE2` | Inputs, selects, boutons secondaires |
| Bordure douce | `#E3E7EA` | Lignes de tableaux, séparateurs légers |

### 5.3 Couleurs sémantiques

Les couleurs sémantiques servent uniquement à communiquer un état métier.

| État | Usage visuel |
|---|---|
| Succès / payé / disponible / prêt | Texte vert sombre, fond vert très pâle, bordure vert clair |
| Information / émise / réservée | Texte bleu, fond bleu très pâle, bordure bleu clair |
| Neutre / brouillon / attente / non terminée | Texte gris sombre, fond gris très pâle, bordure grise |
| Attention / maintenance | Texte orange foncé, fond orange très pâle, bordure orange claire |
| Danger / annulé / erreur | Texte rouge sombre, fond rouge très pâle, bordure rouge claire |
| Remboursement | Texte violet, fond violet très pâle, bordure violette claire |

Règles obligatoires :

- jamais de badge rempli avec une couleur saturée ;
- jamais de texte blanc dans un badge de statut ;
- jamais utiliser la couleur seule pour expliquer un état ;
- un même statut conserve la même couleur dans tous les modules ;
- les couleurs de statut ne remplacent pas Midnight Blue comme couleur de marque.

---

## 6. Typographie

### 6.1 Police unique

La police unique de HMS est **Inter**.

    import { Inter } from "next/font/google";

    const inter = Inter({
      variable: "--font-inter",
      subsets: ["latin"],
      display: "swap",
    });

    body {
      font-family: var(--font-inter), system-ui, sans-serif;
    }

Ne pas utiliser :

- Arial ;
- Geist ;
- serif ;
- police décorative ;
- deuxième police pour les titres ;
- police différente selon le module.

### 6.2 Échelle typographique desktop

| Élément | Taille | Graisse | Traitement |
|---|---:|---:|---|
| Titre de page | 36–40px | 750–800 | Texte Crow, `tracking-tight`, ligne compacte |
| Description de page | 16–18px | 400–500 | Texte secondaire, une ou deux lignes |
| Titre de section | 18–20px | 700 | Texte Crow |
| Titre de card | 16–18px | 700 | Texte Crow |
| Libellé de card statistique | 14px | 500–600 | Texte secondaire |
| Valeur statistique / montant clé | 26–30px | 750–800 | Crow, vert seulement si l’information est positive |
| Entête de colonne | 12–13px | 700 | Uppercase discret, ton secondaire |
| Texte principal de table | 14–15px | 600–700 | Crow |
| Texte secondaire de table | 13–14px | 400–500 | Texte secondaire |
| Champ et bouton | 14px | 600 | Compact et lisible |
| Badge | 12–13px | 600 | Jamais trop petit |

### 6.3 Règles de texte

- utiliser `tracking-tight` seulement pour les titres et les grands chiffres ;
- ne pas écrire de paragraphes en uppercase ;
- garder des libellés en phrase naturelle ;
- utiliser des verbes directs ;
- utiliser `Générer une facture`, `Enregistrer`, `Appliquer les filtres`, `Sélectionner` ;
- ne pas écrire `Soumettre`, `Valider` ou `Confirmer` lorsqu’un terme métier précis existe ;
- utiliser des chiffres tabulaires pour les montants si cela améliore l’alignement dans les tableaux ;
- une description peut être volontairement forcée sur deux lignes lorsqu’elle améliore la lecture du flux.

---

## 7. Espacement, rayons et ombres

### 7.1 Échelle d’espacement

| Nom | Valeur | Utilisation |
|---|---:|---|
| `xs` | 4px | Micro-écart, icône ↔ libellé |
| `sm` | 8px | Badges, actions compactes |
| `md` | 12px | Label ↔ champ, actions proches |
| `lg` | 16px | Groupes internes |
| `xl` | 24px | Padding d’une card, sections proches |
| `2xl` | 32px | Sections principales |
| `3xl` | 40px | Header de page ↔ premier contenu |
| `4xl` | 48px | Padding horizontal desktop |

### 7.2 Rayons

| Élément | Rayon cible |
|---|---:|
| Grande card / tableau / popup / modal | 20–22px |
| Card statistique | 18–20px |
| Bouton standard | 14–16px |
| Champ / select | 14–16px |
| Bouton icon-only | 14–16px |
| Badge | `rounded-full` |
| Conteneur d’icône | 12–14px |

### 7.3 Bordures et ombres

- les cards ont une bordure douce, un fond blanc et une ombre `shadow-sm` discrète ;
- les champs et boutons secondaires utilisent une bordure légère mais visible ;
- les lignes de table utilisent `--hms-soft-border` ;
- ne pas utiliser `shadow-xl`, ombres colorées, double bordure, bordure noire épaisse ou effet 3D.

---

## 8. Shell global : sidebar, topbar et contenu

Toutes les pages applicatives passent par le layout partagé.

    <AppLayout>
      {/* contenu métier */}
    </AppLayout>

### 8.1 Structure

    ┌───────────────────────────┬────────────────────────────────────────────────┐
    │ Sidebar fixe              │ Topbar blanche                                 │
    │                           ├────────────────────────────────────────────────┤
    │                           │ Zone de contenu sur fond Mist Gray              │
    │                           │                                                │
    │                           │ Header de page                                 │
    │                           │ Cards / tableaux / formulaires / détails       │
    └───────────────────────────┴────────────────────────────────────────────────┘

### 8.2 Dimensions desktop de référence

La référence est le rendu desktop à **1440px** puis à **1600px**.

| Élément | Cible |
|---|---:|
| Sidebar | `280px` fixe |
| Topbar | Environ `100px` |
| Padding zone contenu | `40px 48px 48px` |
| Écart header → premier bloc | `32px` à `40px` |
| Écart entre sections | `24px` à `32px` |
| Hauteur d’un bouton standard | `48px` |
| Hauteur d’un input standard | `48px` |

La zone de contenu ne doit jamais sembler collée à la sidebar ou à la topbar.

---

## 9. Sidebar

La sidebar est le socle de navigation visuelle de HMS.

### 9.1 Composition

1. bloc marque ;
2. navigation principale ;
3. espace flexible ;
4. bloc utilisateur ;
5. réglages si cette fonction existe.

### 9.2 Marque

- icône hôtel dans un carré Midnight Blue arrondi ;
- icône blanche ;
- nom **HMS** en gras ;
- sous-texte : `Gérez votre hôtel avec clarté` ;
- le bloc marque ne doit pas être trop grand ;
- il garde une respiration généreuse avant la navigation.

### 9.3 Navigation

| État | Apparence |
|---|---|
| Actif | Fond Midnight Blue, texte blanc, icône blanche, rayon généreux |
| Inactif | Fond transparent, texte atténué, icône gris sombre |
| Hover | Fond primaire très pâle ou gris doux |
| Futur | Entrée normale avec badge `BIENTÔT` discret |
| Désactivé | Visuellement secondaire, non cliquable |

### 9.4 Icônes recommandées

| Module | Icône Lucide |
|---|---|
| Vue générale | `LayoutDashboard` |
| Chambres | `BedDouble` |
| Clients | `UsersRound` |
| Réservations | `CalendarDays` |
| Factures | `FileText` ou `ReceiptText` |
| Housekeeping | `Sparkles` |
| Paramètres | `Settings` |

### 9.5 Mesures

- largeur : `280px` ;
- padding horizontal : `24px` ;
- espace marque ↔ navigation : `44px` à `56px` ;
- hauteur entrée de navigation : environ `48px` ;
- espace entre les entrées : `8px` ;
- aucun libellé ne doit être coupé ;
- le badge `BIENTÔT` reste petit, lisible et secondaire.

### 9.6 Bloc utilisateur

- card légère au bas de la sidebar ;
- fond subtilement teinté ;
- avatar simple ;
- nom de l’utilisateur ou du rôle ;
- sous-texte de session ou contexte ;
- pas de card lourde ou surdimensionnée.

---

## 10. Topbar

### 10.1 Composition

- fond blanc ;
- hauteur stable ;
- bordure basse douce ;
- recherche large ;
- boutons notification et profil à droite.

### 10.2 Recherche

- icône `Search` à gauche ;
- placeholder : `Recherche globale à venir…` quand cette fonctionnalité n’est pas prête ;
- champ blanc ou gris très pâle ;
- bordure douce ;
- pas de bouton de recherche séparé ;
- ne pas simuler une interaction fonctionnelle lorsqu’elle n’existe pas.

### 10.3 Actions à droite

| Contrôle | Traitement |
|---|---|
| Notification | Carré blanc, bordure douce, icône `Bell` sombre |
| Profil | Carré Midnight Blue, icône `UserRound` blanche |
| Action icon-only | Zone cliquable d’au moins 44px, `aria-label` obligatoire |

---

## 11. Header de page

Chaque page métier commence par une zone cohérente.

    Titre de page                                  Action primaire
    Description courte, utile et concrète

### 11.1 Règles

- le titre et l’action primaire sont alignés sur la même ligne à partir de 1024px ;
- l’action principale est à droite ;
- la description est sous le titre ;
- la description ne doit pas être dans une card ;
- ne pas ajouter d’eyebrow décoratif sans information réelle ;
- ne pas répéter le libellé déjà visible dans la sidebar ;
- une page de détail peut afficher un retour et un identifiant au-dessus du titre ;
- une page de création peut placer le bouton retour au-dessus du titre.

### 11.2 Retour et identifiant

Pour une page de création, modification ou détail :

    [ArrowLeft]  Retour à la liste

    Titre de page
    Description utile

Règles :

- le bouton retour est secondaire et discret ;
- il utilise `ArrowLeft` ;
- il est blanc, bordé et compact ;
- il reste au-dessus du titre ;
- le retour n’est jamais l’action primaire ;
- un identifiant peut être ajouté près du retour lorsqu’il apporte du contexte ;
- le header reste hors card.

### 11.3 Action principale

Une page a une seule action primaire visuelle :

- `Générer une facture` ;
- `Nouvelle chambre` ;
- `Créer une réservation` ;
- `Créer une tâche` ;
- `Enregistrer les modifications`.

Elle associe une icône et un libellé clair.

---

## 12. Boutons

### 12.1 Variantes

| Variante | Usage | Apparence |
|---|---|---|
| Primaire | Action principale de l’écran | Midnight Blue, texte blanc |
| Secondaire | Action non critique | Blanc, bordure douce, texte Crow |
| Danger | Action destructive confirmée | Rouge, texte blanc |
| Icon-only secondaire | Action de ligne, impression, notification | Blanc, bordure douce |
| Ghost | Action mineure dans une zone déjà encadrée | Texte sombre, fond transparent |
| Désactivé | Action impossible selon les règles métier | Opacité réduite, curseur interdit |

### 12.2 Forme

- hauteur standard : `48px` ;
- padding horizontal : `16px` à `20px` ;
- icône : `18px` à `20px` ;
- écart icône ↔ texte : `8px` ;
- rayon : `14px` à `16px` ;
- libellé explicite ;
- `cursor-pointer` obligatoire pour une action active.

### 12.3 États

- hover primaire : `--hms-primary-hover` ;
- active primaire : `--hms-primary-active` ;
- hover secondaire : fond gris très pâle ;
- focus : anneau discret Midnight Blue ;
- disabled : opacité réduite, `cursor-not-allowed`, aucun hover actif ;
- aucune animation de scale agressive.

---

## 13. Cards et surfaces

### 13.1 Card standard

Une card regroupe un ensemble logique d’informations ou d’actions.

    <HmsCard className="rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-6 shadow-sm">
      {/* contenu */}
    </HmsCard>

Une card standard possède :

- fond blanc ;
- bordure douce ;
- rayon généreux ;
- padding cohérent ;
- ombre légère ;
- titre uniquement s’il améliore la compréhension ;
- aucune décoration superflue.

### 13.2 Card statistique

Composition :

    libellé                                   pictogramme
    valeur forte
    phrase de contexte

Règles :

- mêmes dimensions dans une rangée ;
- conteneurs d’icône de mêmes largeur et hauteur ;
- une seule icône par card ;
- valeur plus importante que la métadonnée ;
- pas de fond coloré saturé ;
- le vert est utilisé seulement lorsqu’il a une signification métier positive.

### 13.3 Cards de détail

L’ordre recommandé dans une page de détail :

1. synthèse principale ;
2. statut, montant ou priorité ;
3. informations liées ;
4. détails ou lignes ;
5. historique ;
6. notes secondaires.

Ne pas créer une mosaïque de micro-cards si une grande card structurée est plus lisible.

---

## 14. Formulaires

### 14.1 Structure de champ

    Label
    Champ
    Erreur éventuelle
    Aide seulement si elle est nécessaire

### 14.2 Inputs et selects

- hauteur : environ `48px` ;
- fond blanc ;
- bordure douce ;
- rayon `14px` à `16px` ;
- padding horizontal `16px` ;
- label : 14px, semi-gras, texte secondaire ;
- placeholder : gris discret ;
- focus : anneau Midnight Blue léger ;
- erreur : message visible sous le champ, jamais seulement par une bordure rouge.

### 14.3 Grilles

- deux colonnes sur grand desktop pour des champs de même importance ;
- trois colonnes maximum dans un popup de filtres ;
- une colonne quand l’espace devient insuffisant ;
- ne jamais comprimer à l’excès les dates, montants ou actions.

### 14.4 Actions de formulaire

- alignées à droite ;
- `Annuler` est secondaire ;
- `Créer`, `Enregistrer`, `Générer` ou `Appliquer` est primaire ;
- les actions gardent la même hauteur que les boutons du reste de HMS ;
- un formulaire long peut avoir une zone d’actions stable en bas sans cacher le contenu.

---

## 15. Filtres et popovers

Les filtres suivent le modèle de `/invoices`.

### 15.1 Bouton de filtre

Pour une page dense, les filtres sont masqués par défaut derrière un bouton secondaire.

    [ListFilter] Filtrer

### 15.2 Popup de filtres

- fond blanc ;
- bordure douce ;
- rayon `20px` environ ;
- ombre légère ;
- largeur suffisante pour les champs ;
- ancrage logique au bouton ;
- fermeture avec `Escape` ;
- fermeture au clic extérieur ;
- focus géré correctement ;
- interaction accessible.

### 15.3 Organisation interne

    Filtres
    [Champ 1] [Champ 2] [Champ 3]
    [Champ 4] [Du]      [Au]

                               [Réinitialiser] [Appliquer les filtres]

Règles :

- `Du` et `Au` restent sur la même ligne à partir de 1024px ;
- `Réinitialiser` est secondaire avec `RotateCcw` ;
- `Appliquer les filtres` est primaire avec `Check` ;
- le popup ne modifie jamais la logique des filtres existants ;
- le bouton filtre reste accessible lorsqu’aucun filtre n’est actif ;
- un compteur de filtres actifs peut être ajouté seulement s’il est clair et non décoratif.

---

## 16. Tableaux

Les tableaux HMS sont riches mais sobres.

### 16.1 Structure visuelle

    Grande card blanche
      Ligne titre / compteur / outils utiles
      Entête gris très pâle
      Lignes blanches avec séparateurs doux
      Pagination ou actions de bas de page

### 16.2 Règles

- un tableau est placé dans une grande card blanche ;
- l’entête de colonnes a un fond gris très léger ;
- les entêtes sont petits, forts et peu contrastés ;
- les lignes ont une hauteur confortable ;
- la donnée principale est plus forte ;
- la métadonnée est placée dessous, plus petite et atténuée ;
- les montants sont alignés à droite lorsqu’ils forment une colonne ;
- les actions de ligne sont à droite ;
- les actions icon-only sont carrées, blanches et bordées ;
- chaque action icon-only possède un `aria-label`.

### 16.3 Densité desktop

À partir de 1440px :

- un tableau raisonnable est visible sans scroll horizontal ;
- réduire d’abord les paddings et rééquilibrer les colonnes avant de réduire la police ;
- ne pas casser une valeur critique sur plusieurs lignes ;
- dates de séjour et durées restent sur une ligne lorsque l’espace le permet ;
- les colonnes principales reçoivent plus de largeur ;
- la colonne d’actions est la plus étroite ;
- le texte secondaire peut être compact mais jamais illisible.

### 16.4 Tableaux très larges

Sous 1024px seulement, un scroll horizontal ou une présentation en cards est acceptable.

En cas d’adaptation :

1. conserver identité, statut, montant et action ;
2. regrouper les informations secondaires sur une seconde ligne ;
3. garder toutes les actions accessibles ;
4. ne jamais masquer silencieusement une information importante.

---

## 17. Tableaux de sélection

Les tableaux de sélection suivent le modèle visuel de `/invoices/create`.

Ils servent à choisir une ressource avant de remplir un formulaire, générer un document, créer une réservation ou démarrer une action métier.

Exemples :

- sélectionner une réservation pour générer une facture ;
- sélectionner une chambre pour créer une réservation ;
- sélectionner un client pour créer un séjour ;
- sélectionner un agent pour affecter une tâche ;
- sélectionner une tâche pour lancer une opération.

### 17.1 Structure

    Titre de la sélection                              [Compteur contextuel]
    Description courte expliquant ce qui doit être choisi.

    | Ressource | Informations | État | Action |
    | ...       | ...          | Prête | Sélectionner |
    | ...       | ...          | Prête | Sélectionnée |
    | ...       | ...          | Indisponible | Sélectionner désactivé |

### 17.2 Card de sélection

- grande card blanche ;
- titre et description à gauche ;
- compteur ou résumé contextuel discret à droite ;
- entête de tableau gris très pâle ;
- aucune marge excessive entre le titre de la card et le début réel du tableau ;
- compteur compact, aligné à droite, jamais dominant ;
- lignes lisibles, séparées par une bordure douce ;
- aucune décoration inutile.

### 17.3 Ressource sélectionnée

Lorsqu’une ressource pilote le reste du formulaire :

- une seule ressource peut être sélectionnée à la fois ;
- la ligne sélectionnée est légèrement teintée ;
- le bouton devient primaire Midnight Blue ;
- le libellé affiché est `Sélectionnée` ;
- les autres ressources disponibles affichent `Sélectionner` ;
- sélectionner une autre ligne déplace l’état de sélection ;
- l’aperçu et la zone finale doivent refléter la sélection active.

### 17.4 Ressource non disponible

Une ressource non disponible peut rester visible seulement lorsqu’elle apporte une information utile.

Elle doit alors :

- afficher un statut neutre, clair et lisible ;
- conserver son contexte principal ;
- avoir un bouton désactivé ;
- utiliser `cursor-not-allowed` ;
- ne pas être confondue avec une ressource sélectionnable ;
- ne pas encombrer la liste avec des données déjà inutiles.

Les ressources devenues non pertinentes ou impossibles à utiliser ne doivent pas rester affichées sans raison métier ou pédagogique.

### 17.5 Équilibre des colonnes

Les colonnes d’un tableau de sélection doivent être équilibrées selon leur contenu.

Règles :

- la colonne Client ne doit pas prendre une largeur disproportionnée ;
- les colonnes identifiant, ressource, période et montant reçoivent une largeur proportionnelle à leur contenu ;
- les colonnes principales doivent rester équilibrées ;
- une colonne numérique courte comme `Nuits` reste compacte ;
- la colonne État doit être centrée horizontalement ;
- l’entête État doit être centré ;
- les badges ou valeurs d’état doivent être centrés ;
- la colonne Action reste compacte et alignée à droite ;
- éviter tout scroll horizontal à partir de 1440px lorsque le tableau présente un nombre raisonnable de colonnes ;
- réduire d’abord les paddings et ajuster les colonnes avant de réduire fortement la taille du texte.

---

## 18. Badges de statut

### 18.1 Forme

- `rounded-full` ;
- fond pâle ;
- bordure fine ;
- texte semi-gras ;
- icône facultative de 14px à 16px ;
- padding compact.

### 18.2 Exemple Invoice

| Valeur API | Libellé UI | Traitement |
|---|---|---|
| `DRAFT` | Brouillon | Gris |
| `ISSUED` | Émise | Bleu |
| `PAID` | Payée | Vert |
| `CANCELLED` | Annulée | Rouge |
| `REFUNDED` | Remboursée | Violet |

### 18.3 Exemple de sélection

| Situation | Libellé UI | Traitement |
|---|---|---|
| Ressource prête | Prête à facturer / Disponible / Prête | Vert |
| Ressource non terminée | Non terminée | Gris |
| Ressource déjà utilisée | Déjà traitée / Facture existante | À masquer si elle ne sert plus au flux |
| Ressource sélectionnée | Sélectionnée | Bouton primaire, pas badge de statut |

Les mêmes principes sont réutilisés dans les modules Chambres, Réservations, Clients et Housekeeping.

---

## 19. Pages de création, modification et sélection

Les pages de création, modification ou sélection suivent le modèle de `/invoices/create`.

### 19.1 Flux visuel obligatoire

Une page de création doit guider l’utilisateur selon ce flux naturel :

1. choisir ;
2. ajuster ;
3. vérifier ;
4. confirmer.

### 19.2 Structure de page

    [← Retour à la liste]

    Titre de création
    Description utile sur une ou deux lignes.

    Premier bloc métier

    Sélection ou formulaire principal

    Paramètres                    Aperçu
    Champs modifiables            Données calculées ou figées

    Contexte sélectionné                          [Annuler] [Action principale]

### 19.3 Header d’une page de création

Ordre obligatoire :

1. bouton retour secondaire ;
2. titre fort de la page ;
3. description courte et utile ;
4. premier bloc métier.

Règles :

- le bouton retour est discret, blanc, bordé, avec `ArrowLeft` ;
- il reste au-dessus du titre ;
- le titre est noir, fort, sans eyebrow décoratif ;
- la description peut volontairement être limitée à deux lignes lorsque cela améliore la lecture ;
- le header ne doit pas être enfermé dans une card ;
- aucune card informative inutile ne doit s’intercaler entre le header et l’action principale de la page ;
- le premier bloc après le header doit correspondre à l’action réelle : sélection, formulaire ou configuration.

### 19.4 Aide métier

Les règles métier informatives doivent être affichées seulement lorsqu’elles sont utiles.

Règles :

- privilégier une aide courte intégrée à la page ;
- éviter les grandes cards redondantes ;
- ne pas répéter une règle que l’interface démontre déjà clairement ;
- ne jamais supprimer une règle métier réelle ;
- la simplification visuelle ne doit pas modifier le comportement métier.

### 19.5 Formulaire et aperçu sur deux colonnes

Après une sélection, le formulaire et l’aperçu métier forment deux grandes cards sur desktop.

    ┌──────────────────────────────┐  ┌──────────────────────────────┐
    │ Paramètres                   │  │ Aperçu                       │
    │ Champs modifiables           │  │ Données calculées            │
    │ Notes                        │  │ Total et informations clés   │
    └──────────────────────────────┘  └──────────────────────────────┘

Règles :

- les deux cards ont une largeur visuellement équilibrée ;
- elles sont séparées par un espace de 24px à 32px ;
- sur tablette ou mobile, elles se superposent verticalement ;
- la card de gauche contient les champs modifiables ;
- la card de droite contient les données calculées ou figées ;
- les deux cards utilisent les mêmes surfaces, rayons, bordures, ombres et paddings ;
- le formulaire conserve des labels au-dessus des champs ;
- une zone Notes peut être plus haute qu’un input standard ;
- les champs restent spacieux sans devenir surdimensionnés.

### 19.6 Aperçu métier ou financier

L’aperçu contient les informations calculées, liées à la sélection ou figées au moment de l’action.

Règles :

- l’aperçu possède une zone de synthèse interne légèrement teintée ;
- cette zone regroupe les informations liées : client, ressource, séjour, chambre, identifiant ou contexte ;
- les libellés sont secondaires ;
- les valeurs sont plus fortes et plus foncées ;
- les montants ou informations de calcul sont affichés dans une liste verticale lisible ;
- les valeurs importantes sont alignées à droite ;
- la valeur finale utilise une surface distincte mais discrète ;
- le total final ou le résultat final doit être le point de lecture principal de la card ;
- ne pas utiliser de gradient, de surface saturée ou d’ombre forte pour souligner un montant.

### 19.7 Zone finale d’actions

Les formulaires à impact métier utilisent une grande zone finale.

    [Document] Ressource #26 sélectionnée

                                          [Annuler] [Générer la facture]

Règles :

- grande card blanche horizontale ;
- contexte de la sélection à gauche, avec une icône Lucide discrète ;
- actions à droite ;
- bouton Annuler secondaire ;
- action de confirmation primaire Midnight Blue ;
- l’action primaire doit reprendre le verbe métier exact : Générer, Créer, Enregistrer, Planifier, Affecter ;
- la zone doit rester lisible lorsque le contenu principal est long ;
- sur petits écrans, contexte et actions peuvent se superposer verticalement.

### 19.8 Pages de modification

Une page de modification reprend le même langage visuel qu’une page de création :

1. retour ;
2. identifiant contextuel ;
3. titre ;
4. description courte ;
5. grande card de formulaire ;
6. éventuelle card d’aperçu ou de résumé ;
7. actions alignées à droite.

---

## 20. Pages par type

### 20.1 Pages de liste

Exemples :

    /invoices
    /rooms
    /reservations
    /housekeeping/tasks

Ordre recommandé :

1. header de page ;
2. statistiques si elles servent réellement à décider ;
3. barre d’outils ou bouton `Filtrer` ;
4. tableau ;
5. pagination ou état vide.

Référence principale : `/invoices`.

### 20.2 Pages de création

Exemples :

    /invoices/create
    /rooms/create
    /reservations/create
    /housekeeping/tasks/create

Ordre recommandé :

1. retour ;
2. titre ;
3. description courte ;
4. sélection ou premier bloc métier ;
5. formulaire ;
6. aperçu ;
7. zone finale d’actions.

Référence principale : `/invoices/create`.

### 20.3 Pages de détail

Exemples :

    /invoices/[id]
    /rooms/[id]
    /housekeeping/tasks/[id]

Ordre recommandé :

1. retour et identifiant ;
2. titre ;
3. statut et actions contextuelles ;
4. synthèse principale ;
5. montant, priorité ou état clé ;
6. informations liées ;
7. détails ;
8. historique ;
9. notes.

### 20.4 Pages d’historique

- header centré sur la ressource concernée ;
- synthèse courte financière ou opérationnelle ;
- tableau historique ;
- accès cohérent vers un détail ;
- aucune nouvelle esthétique spécifique.

---

## 21. États vides, chargements et erreurs

### 21.1 État vide

Un état vide doit expliquer l’absence de données et proposer l’action logique.

    Aucune facture trouvée
    Modifiez vos filtres ou générez une facture depuis une réservation terminée.
    [Générer une facture]

Règles :

- card blanche simple ;
- icône Lucide discrète si elle apporte un sens ;
- pas d’illustration géante ;
- action claire seulement si une action est possible.

### 21.2 Chargement

- skeleton léger ou message court ;
- jamais de spinner géant ;
- garder la structure de l’écran lorsque possible ;
- ne pas faire bouger excessivement le layout pendant le chargement.

### 21.3 Erreur

- surface claire ;
- titre explicite ;
- explication utile ;
- action de réessai si elle existe ;
- jamais de jargon backend, de stack trace ou de détail technique brut.

---

## 22. Icônes Lucide

### 22.1 Règles

- toute nouvelle icône vient de `lucide-react` ;
- taille habituelle : 18px ou 20px ;
- 16px seulement dans un badge ou une zone très compacte ;
- une icône ne remplace pas un libellé important lorsqu’elle peut être ambiguë ;
- éviter plusieurs icônes pour une même action ;
- les actions icon-only possèdent un `aria-label`.

### 22.2 Icônes communes

| Action | Icône |
|---|---|
| Ajouter / créer | `Plus` |
| Filtrer | `ListFilter` |
| Réinitialiser | `RotateCcw` |
| Appliquer | `Check` |
| Voir | `Eye` |
| Modifier | `Pencil` |
| Imprimer | `Printer` |
| Télécharger | `Download` |
| Retour | `ArrowLeft` |
| Actualiser si nécessaire | `RefreshCw` |
| Désactiver | `Power` |
| Supprimer | `Trash2` |
| Notification | `Bell` |
| Profil | `UserRound` |
| Information | `Info` |
| Document / facture | `FileText` ou `ReceiptText` |

---

## 23. Accessibilité et mouvements

Chaque page respecte les règles suivantes :

- navigation clavier complète ;
- focus visible ;
- ordre de tabulation logique ;
- champs associés à leur label ;
- erreurs associées à leur champ ;
- boutons icon-only avec `aria-label` ;
- popups et modals avec focus trap ;
- fermeture `Escape` ;
- contraste suffisant ;
- pas de couleur seule pour expliquer un état ;
- respect de `prefers-reduced-motion`.

Les animations sont discrètes :

- transition de couleur au hover ;
- opacité courte à l’ouverture d’un popup ;
- aucune animation automatique inutile ;
- aucune animation rebondissante.

---

## 24. Architecture de composants

Les motifs visuels communs doivent être centralisés.

Ne pas recopier des classes Tailwind fragiles dans chaque module.

    frontend/src/components/
    ├── hms/
    │   ├── HmsButton.tsx
    │   ├── HmsCard.tsx
    │   ├── HmsBadge.tsx
    │   ├── HmsInput.tsx
    │   ├── HmsSelect.tsx
    │   ├── HmsIconButton.tsx
    │   ├── HmsPageHeader.tsx
    │   ├── HmsStatsCard.tsx
    │   ├── HmsTable.tsx
    │   ├── HmsSelectionTable.tsx
    │   ├── HmsSummaryCard.tsx
    │   ├── HmsFormActions.tsx
    │   └── HmsEmptyState.tsx
    ├── layout/
    │   ├── AppLayout.tsx
    │   ├── Sidebar.tsx
    │   └── Topbar.tsx
    ├── invoices/
    ├── rooms/
    ├── reservations/
    ├── clients/
    └── housekeeping/

### 24.1 Responsabilités

| Composant | Rôle |
|---|---|
| `AppLayout` | Shell global : sidebar, topbar, zone contenu |
| `Sidebar` | Navigation et état actif |
| `Topbar` | Recherche, notifications, profil |
| `HmsPageHeader` | Titre, description, action principale ou retour |
| `HmsCard` | Surface standard HMS |
| `HmsButton` | Variantes de bouton |
| `HmsIconButton` | Action sans texte accessible |
| `HmsBadge` | Badge de statut cohérent |
| `HmsInput` / `HmsSelect` | Champs cohérents |
| `HmsStatsCard` | Card statistique |
| `HmsTable` | Enveloppe et conventions de tableau |
| `HmsSelectionTable` | Tableau réutilisable avec état de sélection |
| `HmsSummaryCard` | Aperçu financier ou métier |
| `HmsFormActions` | Zone finale avec contexte et actions |
| Composant métier | Données et actions propres au module |

### 24.2 Règle de réutilisation

Créer ou améliorer un composant partagé lorsqu’il :

- apparaît dans deux pages ou plus ;
- porte une règle forte du design system ;
- évite une duplication de classes sensibles ;
- reste indépendant de la logique métier d’un module unique.

Ne pas sur-abstraire un composant à usage unique simple.

---

## 25. Règles Tailwind

### 25.1 À faire

- utiliser les tokens CSS avec `var(--hms-...)` ;
- utiliser `clsx` pour les classes conditionnelles ;
- écrire les classes dans l’ordre : layout → spacing → forme → couleur → typo → interaction ;
- garder les styles structurels dans les composants HMS ;
- ajouter `cursor-pointer` à tout contrôle actif ;
- utiliser l’échelle d’espacement de ce document ;
- ajouter un focus visible à tout contrôle interactif.

### 25.2 À éviter

- `bg-zinc-*`, `text-stone-*`, `border-slate-*` arbitraires dans les nouveaux composants ;
- palette différente par module ;
- `shadow-xl` ou ombres colorées ;
- gradients ;
- styles inline pour les couleurs du design system ;
- conditions Tailwind illisibles sans `clsx` ;
- `min-w-*` qui force un scroll horizontal desktop sans nécessité ;
- second système de boutons ou de cards ;
- code dupliqué au lieu d’un composant partagé évident.

---

## 26. Checklist de validation visuelle

Avant de considérer une page comme terminée, vérifier :

### 26.1 Shell global

- [ ] sidebar proche de 280px sur desktop ;
- [ ] topbar blanche stable ;
- [ ] fond de page Mist Gray ;
- [ ] Inter appliquée ;
- [ ] Midnight Blue limité au primaire et à l’actif ;
- [ ] aucune palette spécifique ajoutée par le module.

### 26.2 Header

- [ ] titre noir, fort et lisible ;
- [ ] une seule action primaire ;
- [ ] description concrète et utile ;
- [ ] alignement propre à 1440px et 1600px ;
- [ ] aucun eyebrow décoratif inutile.

### 26.3 Composants

- [ ] cards blanches, bordure douce, rayon cohérent ;
- [ ] boutons de hauteur cohérente ;
- [ ] champs alignés ;
- [ ] conteneurs d’icônes identiques dans une même série ;
- [ ] badges cohérents ;
- [ ] `cursor-pointer` sur tous les contrôles actifs.

### 26.4 Données

- [ ] table sans scroll horizontal à 1440px lorsque cela est raisonnablement possible ;
- [ ] lignes et colonnes alignées ;
- [ ] montants visibles ;
- [ ] dates et durées non cassées inutilement ;
- [ ] actions icon-only avec `aria-label`.

### 26.5 Pages de création et sélection

- [ ] bouton retour secondaire placé avant le titre ;
- [ ] titre et description hors card ;
- [ ] premier bloc directement utile à l’action métier ;
- [ ] tableau de sélection sans marges inutiles ;
- [ ] compteur contextuel compact et aligné ;
- [ ] état sélectionné immédiatement identifiable ;
- [ ] une seule action de sélection active lorsque le flux le demande ;
- [ ] statuts centrés dans leur colonne ;
- [ ] colonnes équilibrées sans largeur excessive ;
- [ ] formulaire et aperçu équilibrés sur desktop ;
- [ ] données calculées clairement hiérarchisées ;
- [ ] total ou résultat final visuellement dominant sans surcharge ;
- [ ] zone finale avec contexte à gauche et actions à droite ;
- [ ] aucune modification des règles métier pour simplifier le design.

### 26.6 États

- [ ] chargement cohérent ;
- [ ] erreur claire ;
- [ ] état vide utile ;
- [ ] popup et modal fermables au clavier ;
- [ ] rendu acceptable sous 1024px.

---

## 27. Processus obligatoire pour une nouvelle interface

1. Identifier le type de page : liste, création, modification, détail, historique ou sélection.
2. Lire ce fichier intégralement.
3. Lire les composants HMS et layout réellement utilisés.
4. Réutiliser `AppLayout`.
5. Choisir la référence adaptée :
   - `/invoices` pour une liste, un tableau, des statistiques ou des filtres ;
   - `/invoices/create` pour une création, une sélection, un formulaire, un aperçu ou une confirmation.
6. Construire le header selon le modèle HMS.
7. Réutiliser les composants partagés avant d’écrire du style spécifique.
8. Implémenter uniquement le design sans toucher aux contrats métier.
9. Vérifier la page à 1440px et 1600px.
10. Vérifier un rendu tablette sous 1024px.
11. Lancer `npm run lint` depuis `frontend/`.
12. Faire valider visuellement avant tout commit.

---

## 28. Interdictions explicites

Ne pas :

- remplacer Inter ;
- ajouter une deuxième couleur de marque ;
- ajouter une deuxième famille typographique ;
- utiliser des gradients ;
- transformer le dashboard en site marketing ;
- mettre chaque information dans une card ;
- rendre chaque action primaire ;
- utiliser une autre bibliothèque d’icônes pour du nouveau code si Lucide couvre le besoin ;
- modifier un comportement métier pour simplifier l’interface ;
- rendre un tableau scrollable horizontalement sur desktop sans besoin réel ;
- supprimer une donnée métier importante au lieu de la structurer ;
- créer des badges surdimensionnés ;
- utiliser des ombres fortes pour simuler la hiérarchie ;
- laisser plusieurs ressources sélectionnées lorsqu’une seule sélection est attendue ;
- lancer un commit sans validation visuelle explicite.

---

## 29. Prompt de référence pour Codex ou OpenCode

Pour tout travail frontend futur, commencer le prompt avec ce bloc :

    Lis intégralement README-FRONTEND-DESIGN.md à la racine du projet avant toute modification.
    Ce fichier est la source de vérité du design HMS.

    Utilise /invoices comme référence pour les pages de liste, statistiques, filtres, tableaux et pagination.

    Utilise /invoices/create comme référence pour les pages de création, modification, sélection, formulaire, aperçu métier ou financier et actions finales.

    Toute page modifiée doit reprendre exactement le même shell, les mêmes tokens, la même typographie Inter, les mêmes proportions, les mêmes surfaces, les mêmes boutons, les mêmes champs, les mêmes badges, les mêmes états sélectionnés et la même densité visuelle.

    Ne touche pas aux règles métier, aux routes, aux services API, aux types TypeScript, aux validations, aux schémas Zod ni aux données.

    Utilise lucide-react pour toute nouvelle icône.
    Ajoute cursor-pointer à tout contrôle actif.

    Avant toute modification, lis aussi AGENTS.md, le skill frontend-design local et les composants réellement utilisés par la page concernée.

Pour un restyling de page, ajouter :

    Restyle uniquement la page demandée.
    Ne modifie pas les autres pages ni le layout global sans instruction explicite.

    Après la modification, lance npm run lint depuis frontend/, liste les fichiers modifiés, explique brièvement quoi vérifier visuellement, puis attends ma validation avant git add ou commit.

---

## 30. Définition de terminé

Une page respecte le design system HMS lorsqu’elle :

- est immédiatement reconnaissable comme une page HMS ;
- semble appartenir à la même application que `/invoices` et `/invoices/create` ;
- reprend les mêmes proportions, surfaces, couleurs, typographie et comportements ;
- reste fidèle aux données et règles métier de son module ;
- est claire pour la réception comme pour le management ;
- guide naturellement l’utilisateur dans son flux ;
- reste professionnelle sans dépendre d’effets décoratifs.

> **La cohérence est prioritaire sur la nouveauté.**
