# HMS — Frontend Design System

> **Référence officielle du design HMS**  
> **Fichier à placer à la racine du dépôt : `README-FRONTEND-DESIGN.md`**  
> La page `/invoices` validée est la référence de qualité, de densité, d’espacement, de composants et de hiérarchie visuelle.  
> Toute nouvelle interface HMS doit sembler avoir été conçue par le même développeur frontend, pour le même produit, au même moment.

---

## 1. Rôle de ce document

HMS est une application de gestion hôtelière destinée à la réception, au management et, à terme, aux équipes housekeeping.

Ce document définit la **langue visuelle unique** de l’application. Il sert de source de vérité pour créer ou restyler :

- les pages de liste ;
- les pages de création et de modification ;
- les pages de détail ;
- les historiques ;
- les formulaires ;
- les tableaux ;
- les popups de filtres ;
- les états vides, erreurs et chargements ;
- les composants partagés.

L’objectif n’est pas de produire des pages différentes et décoratives selon les modules. L’objectif est d’obtenir une application cohérente, claire, calme et crédible pour une démonstration professionnelle.

La règle principale est simple :

> **La cohérence avec `/invoices` est prioritaire sur toute nouvelle idée visuelle.**

---

## 2. Référence visuelle officielle

### 2.1 Page de référence

La route de référence est :

```text
/invoices
```

Elle fixe notamment :

- la largeur de la sidebar ;
- la hauteur et la structure de la topbar ;
- la couleur du fond de contenu ;
- la hiérarchie de titre ;
- la largeur du contenu ;
- le style des cards ;
- la taille des boutons ;
- les rayons ;
- les ombres ;
- la densité des tableaux ;
- les badges de statut ;
- les popups de filtres ;
- les espacements verticaux et horizontaux.

### 2.2 Ordre de priorité en cas de doute

Lorsqu’un choix visuel doit être fait, appliquer cet ordre :

1. les captures validées de `/invoices` ;
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
- Headless UI autorisé uniquement pour des comportements accessibles : `Dialog`, `Menu`, `Listbox`, `Popover`, `Transition`.

### 3.2 Respect du métier

Un changement frontend esthétique ne doit jamais modifier :

- les routes ;
- les appels API ;
- les services fetch ;
- les paramètres de requête ;
- les types TypeScript métier ;
- les schémas Zod ;
- les mocks ;
- les validations métier ;
- les calculs ;
- les règles de statut ;
- les données affichées.

Les composants métier ne réalisent pas directement les appels API. Les appels restent dans les services existants.

### 3.3 Interactions

- tout bouton, lien visuellement cliquable, action d’icône, onglet et ligne interactive utilise `cursor-pointer` ;
- un contrôle réellement désactivé utilise `disabled` et `cursor-not-allowed` ;
- les boutons d’icône possèdent un `aria-label` ;
- tout nouveau contrôle clavier doit conserver un focus visible ;
- ne pas introduire de nouvel UI kit.

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
- élégant sans devenir décoratif.

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
- interface trop arrondie, enfantine ou “SaaS générique”.

---

## 5. Identité visuelle et tokens

Les nouvelles couleurs ne doivent pas être inventées dans les composants. Les tokens doivent rester centralisés dans :

```text
frontend/src/app/globals.css
```

### 5.1 Tokens officiels

```css
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
```

### 5.2 Palette fonctionnelle

| Usage | Valeur | Règle |
|---|---:|---|
| Action primaire / navigation active | `#191970` | Réservée à l’action principale, menu actif, profil et focus |
| Hover primaire | `#15155f` | Utilisée uniquement lors du survol d’un élément primaire |
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
| Succès / payé / disponible | texte vert sombre, fond vert très pâle, bordure vert clair |
| Information / émise / réservée | texte bleu, fond bleu très pâle, bordure bleu clair |
| Neutre / brouillon / attente | texte gris sombre, fond gris très pâle, bordure grise |
| Attention / maintenance | texte orange foncé, fond orange très pâle, bordure orange claire |
| Danger / annulé / erreur | texte rouge sombre, fond rouge très pâle, bordure rouge claire |
| Remboursement | texte violet, fond violet très pâle, bordure violette claire |

Règles obligatoires :

- jamais de badge rempli avec une couleur saturée ;
- jamais de texte blanc dans un badge de statut ;
- jamais la couleur seule pour expliquer un état ;
- un même statut conserve la même couleur dans tous les modules ;
- les couleurs de statut ne remplacent pas Midnight Blue comme couleur de marque.

---

## 6. Typographie

### 6.1 Police unique

La police unique de HMS est **Inter**.

```tsx
import { Inter } from "next/font/google";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});
```

```css
body {
  font-family: var(--font-inter), system-ui, sans-serif;
}
```

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
| Titre de page | 36–40px | 750–800 | texte Crow, `tracking-tight`, ligne compacte |
| Description de page | 16–18px | 400–500 | texte secondaire, deux lignes maximum |
| Titre de section | 18–20px | 700 | texte Crow |
| Titre de card | 16–18px | 700 | texte Crow |
| Libellé de card statistique | 14px | 500–600 | texte secondaire |
| Valeur statistique / montant clé | 26–30px | 750–800 | Crow, vert uniquement lorsqu’il indique une information positive utile |
| Entête de colonne | 12–13px | 700 | uppercase discret, ton secondaire |
| Texte principal de table | 14–15px | 600–700 | Crow |
| Texte secondaire de table | 13–14px | 400–500 | texte secondaire |
| Champ et bouton | 14px | 600 | compact et lisible |
| Badge | 12–13px | 600 | jamais trop petit |

### 6.3 Règles de texte

- utiliser `tracking-tight` seulement pour les titres et les grands chiffres ;
- ne pas écrire de paragraphes en uppercase ;
- garder des libellés en phrase naturelle ;
- utiliser des verbes directs : `Générer une facture`, `Enregistrer`, `Appliquer les filtres` ;
- ne pas écrire `Soumettre`, `Valider` ou `Confirmer` lorsqu’un terme métier précis existe ;
- utiliser des chiffres tabulaires pour les montants si cela améliore l’alignement dans les tableaux.

---

## 7. Espacement, rayons et ombres

### 7.1 Échelle d’espacement

| Nom | Valeur | Utilisation |
|---|---:|---|
| `xs` | 4px | micro-écart, icône ↔ libellé |
| `sm` | 8px | badges, actions compactes |
| `md` | 12px | label ↔ champ, actions proches |
| `lg` | 16px | groupes internes |
| `xl` | 24px | padding d’une card, sections proches |
| `2xl` | 32px | sections principales |
| `3xl` | 40px | header de page ↔ premier contenu |
| `4xl` | 48px | padding horizontal desktop |

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

- Les cards ont une bordure douce, un fond blanc et une ombre `shadow-sm` discrète.
- Les champs et boutons secondaires utilisent une bordure légère mais visible.
- Les lignes de table utilisent `--hms-soft-border`.
- Ne pas utiliser `shadow-xl`, d’ombres colorées, de double bordure, de bordure noire épaisse ou d’effet 3D.

---

## 8. Shell global : sidebar, topbar et contenu

Toutes les pages applicatives passent par le layout partagé :

```tsx
<AppLayout>
  {/* contenu métier */}
</AppLayout>
```

### 8.1 Structure

```text
┌───────────────────────────┬────────────────────────────────────────────────┐
│ Sidebar fixe              │ Topbar blanche                                 │
│                           ├────────────────────────────────────────────────┤
│                           │ Zone de contenu sur fond Mist Gray              │
│                           │                                                │
│                           │ Header de page                                 │
│                           │ Cards / tableaux / formulaires / détails       │
└───────────────────────────┴────────────────────────────────────────────────┘
```

### 8.2 Dimensions desktop de référence

La référence est le rendu desktop à **1440px** puis à **1600px**.

| Élément | Cible |
|---|---:|
| Sidebar | `280px` fixe |
| Topbar | environ `100px` |
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
| Actif | fond Midnight Blue, texte blanc, icône blanche, rayon généreux |
| Inactif | fond transparent, texte atténué, icône gris sombre |
| Hover | fond primaire très pâle ou gris doux |
| Futur | entrée normale avec badge `BIENTÔT` discret |
| Désactivé | visuellement secondaire, non cliquable |

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
| Notification | carré blanc, bordure douce, icône `Bell` sombre |
| Profil | carré Midnight Blue, icône `UserRound` blanche |
| Action icon-only | zone cliquable d’au moins 44px, `aria-label` obligatoire |

---

## 11. Header de page

Chaque page métier commence par une zone cohérente :

```text
Titre de page                                  Action primaire
Description courte, utile et concrète
```

### 11.1 Règles

- le titre et l’action primaire sont alignés sur la même ligne à partir de 1024px ;
- l’action principale est à droite ;
- la description est sous le titre ;
- la description ne doit pas être dans une card ;
- ne pas ajouter d’eyebrow décoratif sans information réelle ;
- ne pas répéter le libellé déjà visible dans la sidebar ;
- une page de détail peut afficher un retour et un identifiant au-dessus du titre.

### 11.2 Retour et identifiant

Pour une page de création, modification ou détail :

```text
[ArrowLeft]  INV-2026-000012
Titre de page
Description utile
```

- le bouton retour est secondaire et discret ;
- l’identifiant est un micro-libellé secondaire ;
- le retour n’est jamais l’action primaire de la page.

### 11.3 Action principale

Une page a une seule action primaire visuelle :

- `Générer une facture` ;
- `Nouvelle chambre` ;
- `Créer une réservation` ;
- `Créer une tâche`.

Elle associe une icône et un libellé clair.

---

## 12. Boutons

### 12.1 Variantes

| Variante | Usage | Apparence |
|---|---|---|
| Primaire | action principale de l’écran | Midnight Blue, texte blanc |
| Secondaire | action non critique | blanc, bordure douce, texte Crow |
| Danger | action destructive confirmée | rouge, texte blanc |
| Icon-only secondaire | action de ligne, impression, notification | blanc, bordure douce |
| Ghost | action mineure dans une zone déjà encadrée | texte sombre, fond transparent |

### 12.2 Forme

- hauteur standard : `48px` ;
- padding horizontal : `16px` à `20px` ;
- icône : `18px` à `20px` ;
- écart icône ↔ texte : `8px` ;
- rayon : `14px` à `16px` ;
- libellé explicite ;
- `cursor-pointer` obligatoire.

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

```tsx
<HmsCard className="rounded-[20px] border border-[var(--hms-soft-border)] bg-white p-6 shadow-sm">
  {/* contenu */}
</HmsCard>
```

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

```text
libellé                                   pictogramme
valeur forte
phrase de contexte
```

Règles :

- mêmes dimensions dans une rangée ;
- conteneurs d’icône de mêmes largeur et hauteur ;
- une seule icône par card ;
- valeur plus importante que la métadonnée ;
- pas de fond coloré saturé ;
- le vert n’est utilisé que lorsqu’il a une signification métier positive.

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

```text
Label
Champ
Erreur éventuelle
Aide seulement si elle est nécessaire
```

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

Pour une page dense, les filtres sont masqués par défaut derrière un bouton secondaire :

```text
[ListFilter] Filtrer
```

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

```text
Filtres
[Champ 1] [Champ 2] [Champ 3]
[Champ 4] [Du]      [Au]

                           [Réinitialiser] [Appliquer les filtres]
```

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

```text
Grande card blanche
  Ligne titre / compteur / outils utiles
  Entête gris très pâle
  Lignes blanches avec séparateurs doux
  Pagination en bas
```

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
- chaque action icon-only a un `aria-label`.

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

## 17. Badges de statut

### 17.1 Forme

- `rounded-full` ;
- fond pâle ;
- bordure fine ;
- texte semi-gras ;
- icône facultative de 14px à 16px ;
- padding compact.

### 17.2 Exemple Invoice

| Valeur API | Libellé UI | Traitement |
|---|---|---|
| `DRAFT` | Brouillon | gris |
| `ISSUED` | Émise | bleu |
| `PAID` | Payée | vert |
| `CANCELLED` | Annulée | rouge |
| `REFUNDED` | Remboursée | violet |

Les mêmes principes sont réutilisés dans les modules Chambres, Réservations et Housekeeping.

---

## 18. Pages par type

### 18.1 Pages de liste

Exemples :

```text
/invoices
/rooms
/reservations
/housekeeping/tasks
```

Ordre recommandé :

1. header de page ;
2. statistiques si elles servent réellement à décider ;
3. barre d’outils ou bouton `Filtrer` ;
4. tableau ;
5. pagination ou état vide.

### 18.2 Création et modification

Exemples :

```text
/invoices/create
/rooms/create
/rooms/[id]/edit
```

Ordre recommandé :

1. retour ;
2. identifiant ou micro-libellé si utile ;
3. titre ;
4. description courte ;
5. grande card de formulaire ;
6. éventuelle card d’aperçu ;
7. actions alignées à droite.

Règles :

- les formulaires respirent ;
- labels au-dessus des champs ;
- deux colonnes équilibrées sur desktop ;
- zones de texte généreuses quand nécessaire ;
- aucune logique métier ne disparaît pour simplifier visuellement l’écran.

### 18.3 Pages de détail

Exemples :

```text
/invoices/[id]
/rooms/[id]
/housekeeping/tasks/[id]
```

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

### 18.4 Pages d’historique

- header centré sur la ressource concernée ;
- synthèse courte financière ou opérationnelle ;
- tableau historique ;
- accès cohérent vers un détail ;
- aucune nouvelle esthétique spécifique.

---

## 19. États vides, chargements et erreurs

### 19.1 État vide

Un état vide doit expliquer l’absence de données et proposer l’action logique.

```text
Aucune facture trouvée
Modifiez vos filtres ou générez une facture depuis une réservation terminée.
[Générer une facture]
```

Règles :

- card blanche simple ;
- icône Lucide discrète si elle apporte un sens ;
- pas d’illustration géante ;
- action claire seulement si une action est possible.

### 19.2 Chargement

- skeleton léger ou message court ;
- jamais de spinner géant ;
- garder la structure de l’écran lorsque possible ;
- ne pas faire bouger excessivement le layout pendant le chargement.

### 19.3 Erreur

- surface claire ;
- titre explicite ;
- explication utile ;
- action de réessai si elle existe ;
- jamais de jargon backend, de stack trace ou de détail technique brut.

---

## 20. Icônes Lucide

### 20.1 Règles

- toute nouvelle icône vient de `lucide-react` ;
- taille habituelle : 18px ou 20px ;
- 16px seulement dans un badge ou une zone très compacte ;
- une icône ne remplace pas un libellé important lorsqu’elle peut être ambiguë ;
- éviter plusieurs icônes pour une même action ;
- les actions icon-only possèdent un `aria-label`.

### 20.2 Icônes communes

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

---

## 21. Accessibilité et mouvements

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

## 22. Architecture de composants

Les motifs visuels communs doivent être centralisés. Ne pas recopier des classes Tailwind fragiles dans chaque module.

```text
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
```

### 22.1 Responsabilités

| Composant | Rôle |
|---|---|
| `AppLayout` | shell global : sidebar, topbar, zone contenu |
| `Sidebar` | navigation et état actif |
| `Topbar` | recherche, notifications, profil |
| `HmsPageHeader` | titre, description, action principale |
| `HmsCard` | surface standard HMS |
| `HmsButton` | variantes de bouton |
| `HmsIconButton` | action sans texte accessible |
| `HmsBadge` | badge de statut cohérent |
| `HmsInput` / `HmsSelect` | champs cohérents |
| `HmsStatsCard` | card statistique |
| `HmsTable` | enveloppe et conventions de tableau |
| Composant métier | données et actions propres au module |

### 22.2 Règle de réutilisation

Créer ou améliorer un composant partagé lorsqu’il :

- apparaît dans deux pages ou plus ;
- porte une règle forte du design system ;
- évite une duplication de classes sensibles ;
- reste indépendant de la logique métier d’un module unique.

Ne pas sur-abstraire un composant à usage unique simple.

---

## 23. Règles Tailwind

### 23.1 À faire

- utiliser les tokens CSS avec `var(--hms-...)` ;
- utiliser `clsx` pour les classes conditionnelles ;
- écrire les classes dans l’ordre : layout → spacing → forme → couleur → typo → interaction ;
- garder les styles structurels dans les composants HMS ;
- ajouter `cursor-pointer` à tout contrôle actif ;
- utiliser l’échelle d’espacement de ce document ;
- ajouter un focus visible à tout contrôle interactif.

### 23.2 À éviter

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

## 24. Checklist de validation visuelle

Avant de considérer une page comme terminée, vérifier :

### Shell global

- [ ] sidebar proche de 280px sur desktop ;
- [ ] topbar blanche stable ;
- [ ] fond de page Mist Gray ;
- [ ] Inter appliquée ;
- [ ] Midnight Blue limité au primaire et à l’actif ;
- [ ] aucune palette spécifique ajoutée par le module.

### Header

- [ ] titre noir, fort et lisible ;
- [ ] une seule action primaire ;
- [ ] description concrète et utile ;
- [ ] alignement propre à 1440px et 1600px.

### Composants

- [ ] cards blanches, bordure douce, rayon cohérent ;
- [ ] boutons de hauteur cohérente ;
- [ ] champs alignés ;
- [ ] conteneurs d’icônes identiques dans une même série ;
- [ ] badges cohérents ;
- [ ] `cursor-pointer` sur tous les contrôles actifs.

### Données

- [ ] table sans scroll horizontal à 1440px lorsque cela est raisonnablement possible ;
- [ ] lignes et colonnes alignées ;
- [ ] montants visibles ;
- [ ] dates et durées non cassées inutilement ;
- [ ] actions icon-only avec `aria-label`.

### États

- [ ] chargement cohérent ;
- [ ] erreur claire ;
- [ ] état vide utile ;
- [ ] popup et modal fermables au clavier ;
- [ ] rendu acceptable sous 1024px.

---

## 25. Processus obligatoire pour une nouvelle interface

1. Identifier le type de page : liste, création, modification, détail ou historique.
2. Lire ce fichier intégralement.
3. Lire les composants HMS et layout réellement utilisés.
4. Réutiliser `AppLayout`.
5. Construire le header selon le modèle HMS.
6. Réutiliser les composants partagés avant d’écrire du style spécifique.
7. Implémenter uniquement le design sans toucher aux contrats métier.
8. Vérifier la page à 1440px et 1600px.
9. Vérifier un rendu tablette sous 1024px.
10. Lancer `npm run lint` depuis `frontend/`.
11. Faire valider visuellement avant tout commit.

---

## 26. Interdictions explicites

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
- lancer un commit sans validation visuelle explicite.

---

## 27. Prompt de référence pour OpenCode

Pour tout travail frontend futur, commencer le prompt avec ce bloc :

```text
Lis intégralement README-FRONTEND-DESIGN.md à la racine du projet avant toute modification.
Ce fichier est la source de vérité du design HMS.
La page /invoices validée est la référence visuelle.
Toute page modifiée doit reprendre exactement le même shell, les mêmes tokens, la même typographie Inter, les mêmes proportions, les mêmes surfaces, les mêmes boutons, les mêmes champs, les mêmes badges et la même densité visuelle.

Ne touche pas aux règles métier, aux routes, aux services API, aux types TypeScript, aux validations, aux schémas Zod ni aux données.
Utilise lucide-react pour toute nouvelle icône.
Ajoute cursor-pointer à tout contrôle actif.
Avant toute modification, lis aussi AGENTS.md, le skill frontend-design local et les composants réellement utilisés par la page concernée.
```

Pour un restyling de page, ajouter :

```text
Restyle uniquement la page demandée. Ne modifie pas les autres pages ni le layout global sans instruction explicite.
Après la modification, lance npm run lint depuis frontend/, liste les fichiers modifiés, explique brièvement quoi vérifier visuellement, puis attends ma validation avant git add ou commit.
```

---

## 28. Définition de terminé

Une page respecte le design system HMS lorsqu’elle :

- est immédiatement reconnaissable comme une page HMS ;
- semble appartenir à la même application que `/invoices` ;
- reprend les mêmes proportions, surfaces, couleurs, typographie et comportements ;
- reste fidèle aux données et règles métier de son module ;
- est claire pour la réception comme pour le management ;
- reste professionnelle sans dépendre d’effets décoratifs.

> **La cohérence est prioritaire sur la nouveauté.**
