# Récapitulatif Final : Rôle Attaquante (Personne B)

**Auteur** : Ameny Dhouady (Attaquante)  
**Binôme** : Khouloud Boumaiza (Défenseur)  
**Projet** : Projet 2 : Attaquer son propre détecteur (phishing par URL)  
**Date** : Novembre 2026  

---

## 1. Fichiers créés / modifiés et historique Git

### Fichiers livrés
- `src/attack.py` : Fonctions d'attaque boîte noire (`greedy_attack`, `random_attack`), vérifications de plausibilité (`is_valid`, `is_valid_structure`), génération de mutations autorisées et gestion des bornes `set_bounds(S.hi)`.
- `02_attaquant.ipynb` : Notebook complet de l'attaquant, exécuté de haut en bas sans erreur avec tous les graphiques et tableaux de résultats inline.
- `results/modele_menace_operations.csv` : Tableau formalisé du modèle de menace et des opérations autorisées avec leurs coûts.
- `results/attaque_gloutonne_avant.csv` : Traces complètes de l'attaque gloutonne au budget de référence $B_{ref} = 6$.
- `results/attaque_aleatoire_avant.csv` : Traces complètes de l'attaque aléatoire au budget de référence $B_{ref} = 6$.
- `results/rappel_vs_budget_avant.csv` : Mesures du rappel du détecteur sous attaque selon les 8 budgets d'amplitude.
- `figures/rappel_vs_budget_avant.png` : Graphique de la courbe Rappel vs Amplitude de perturbation (gloutonne vs aléatoire).
- `results/realisme.csv` : Taux de conformité des 4 contrôles de plausibilité et réalisme.
- `results/exemples_attaques.csv` : Tableau de 10 exemples concrets avant / après attaque avec scores et mutations.
- `results/transfert.csv` : Résultats de l'évaluation de transférabilité de Random Forest vers XGBoost.
- `RECAP_ATTAQUANT.md` : Le présent document de synthèse.

> **Règle d'intégrité respectée** : `src/common.py` et `01_defenseur.ipynb` n'ont **JAMAIS** été modifiés. Aucune donnée brute (`data/`) ni artefact (`artifacts/`, `*.joblib`) n'a été versionné dans git.

### Commits réalisés (`git log --oneline`)
```text
8ed29d4 Attaquant : modèle de menace, mesures, réalisme, transfert
52a4cf1 Attaquant : opérations autorisées, règles de cohérence, attaque gloutonne et aléatoire
23b03ee Défenseur : nettoyage, découpage par domaine, audit, modèles, seuil
b47221c Défenseur : variables d'URL, métriques, détecteur, profils v1/v2
fd3052a Initial : structure du projet, README, requirements, gitignore
```

### État du push distant
- Commande exécutée : `git push -u origin attacker`
- Résultat : **Refusé (HTTP 403)**  
  `remote: Permission to khouloudboumaiza/projet2-ml-d-tection-de-phishing-par-URL.git denied to ameny-dhaouadi.`
- **Action requise** : Khouloud doit ajouter le compte GitHub `ameny-dhaouadi` comme collaboratrice avec droits d'écriture sur le dépôt GitHub.

---

## 2. Modèle de menace et tableau des opérations

L'attaquant opère sous l'hypothèse d'une **boîte noire stricte** :
- Accès exclusif à l'oracle `det.score(urls)` (probabilité de phishing).
- Aucune connaissance des poids, de l'architecture d'arbres ou du jeu d'entraînement.
- Mutations appliquées directement sur la chaîne de caractères de l'URL (espace du problème). Les variables sont recalculées automatiquement par l'extracteur, garantissant une cohérence cross-features parfaite.
- Plafond strict de requêtes fixé à `MAX_QUERIES = 1000`.

### Tableau des opérations autorisées et coûts
| Composante URL | Opération | Catégorie | Coût | Variables `FEATURES` impactées | Justification technique |
|---|---|---|:---:|---|---|
| **Paramètres de requête (GET)** | `add_query_param` | Librement modifiable | **1** | `query_len`, `n_equal`, `n_amp`, `n_qmark`, `url_len`, `entropy_url` | Ignorés par le serveur cible ou utilisés pour le tracking ; n'altèrent pas l'affichage de la page piégée. |
| **Segment de chemin neutre** | `add_path_segment` | Librement modifiable | **1** | `path_len`, `n_slash`, `n_path_segments`, `url_len`, `entropy_url` | Les routes ou répertoires virtuels (`/en`, `/index`) sont gérés de manière transparente par réécriture d'URL ou reverse-proxy. |
| **Tirets / chiffres dans chemin** | `add_path_hyphen_digits` | Librement modifiable | **1** | `n_hyphen_url`, `n_digits_url`, `digit_ratio`, `max_digit_run` | L'insertion d'identifiants ou de séparateurs dans les routes d'API est triviale à router côté backend. |
| **Retrait de mot sensible du chemin** | `remove_sensitive_path` | Modifiable avec coût | **2** | `n_sensitive`, `n_path_sensitive`, `path_len` | Oblige à refondre l'architecture des endpoints et complique l'ingénierie sociale (masquer `login`, `verify`). |
| **Ajout d'un sous-domaine** | `add_subdomain` | Modifiable avec coût | **2** | `n_sub`, `host_len`, `n_dots`, `host_entropy`, `n_host_tokens` | Nécessite la création et la propagation d'enregistrements DNS (`A` ou `CNAME`) sur la zone contrôlée. |
| **Domaine enregistrable** | `reg_domain` | **Interdit (Coût $\infty$)** | $\infty$ | `reg_domain`, `host_len`, `n_hyphen_host` | Sanctuarisé : changer de domaine ferait perdre le contrôle du serveur hébergeant le phishing. |
| **TLD (Extension)** | Modifier le TLD | **Interdit (Coût $\infty$)** | $\infty$ | `tld_len`, `host_len` | Indissociable du nom de domaine enregistré auprès du registrar. |
| **Schéma** | `http` $\leftrightarrow$ `https` | **Interdit (Coût $\infty$)** | $\infty$ | `is_https` | Fixé par le certificat SSL et exclu du profil `v2` pour éviter les artefacts de collecte. |

---

## 3. Chiffres clés obtenus

*Note méthodologique : Les résultats ci-dessous ont été obtenus en mode rapide (`MAX_ROWS=30000`, `N_ATTACK=200`) sur le jeu de validation découpé sans fuite par domaine.*

### A. Évasion au budget de référence ($B_{ref} = 6$)
- Détecteur ciblé : **XGBoost** (`xgb`), seuil d'alerte figé par le défenseur à `0.1073` (taux de faux positifs $\le 1\%$ sur validation).
- Échantillon évalué : 200 URL de phishing réelles issues de la validation, **toutes détectées au départ** (`score0 >= 0.1073`).
- **Attaque gloutonne** :
  - **Taux d'évasion : 34.0 %** (le rappel du détecteur s'effondre de 100 % à 66.0 %).
  - Requêtes moyennes : **90.8 requêtes** (Médiane : 86.0 | Max : 240 $\ll 1000$).
  - Coût moyen dépensé : 0.34.
- **Attaque aléatoire** :
  - **Taux d'évasion : 8.0 %** (rappel résiduel élevé de 92.0 %).
  - Requêtes moyennes : **5.5 requêtes** (Médiane : 6.0 | Max : 7).
  - Coût moyen dépensé : 0.13.

### B. Évolution du rappel en fonction de l'amplitude (Budget)
Le rappel sous attaque mesure le pourcentage de phishing encore détectés après tentative d'évasion :

| Budget $B$ | Rappel Glouton (%) | Rappel Aléatoire (%) | Interprétation |
|:---:|:---:|:---:|---|
| **0** | **100.0 %** | 100.0 % | Aucune perturbation autorisée (baseline). |
| **1** | **66.0 %** | 88.5 % | **Chute immédiate** : un simple paramètre GET (coût 1) suffit pour la quasi-totalité des évasions. |
| **2** | **66.0 %** | 94.0 % | Saturation rapide du gradient d'évasion. |
| **3** | **66.0 %** | 92.0 % | Stabilité du front d'attaque. |
| **4** | **66.0 %** | 92.0 % | Stabilité du front d'attaque. |
| **6** ($B_{ref}$) | **66.0 %** | 92.0 % | Écart significatif de 26 points entre guidage par score et hasard. |
| **8** | **66.0 %** | 92.0 % | Aucun gain supplémentaire : les phishing restants sont bloqués sur leur domaine. |
| **12** | **66.0 %** | 92.0 % | Plafond d'évasion atteint sous la contrainte du `reg_domain`. |

### C. Réalisme et contrôles de plausibilité
Évalué sur 100 % des URL modifiées ayant réussi l'évasion :
1. **Domaine enregistrable inchangé** (`reg_domain(adv) == reg_domain(orig)`) : **100.0 %**
2. **Structure et syntaxe conformes** (1 seul `?`, pas de `//`, parsabilité `urlsplit`) : **100.0 %**
3. **Longueur maximale réaliste** ($\le 2000$ caractères) : **100.0 %**
4. **Plausibilité statistique absolue** (Toutes les 32 variables $\le S.hi$ quantile 99.9 % du train) : **100.0 %**

### D. Extension Transférabilité (Random Forest $\rightarrow$ XGBoost)
Attaque construite en boîte noire sur le modèle de substitution local **Random Forest**, puis rejouée contre **XGBoost** (sans **aucune requête** adressée à XGBoost pendant la recherche) :
- Évasion directe sur XGBoost (oracle XGBoost) : **34.0 %**
- Évasion directe sur Random Forest (oracle RF) : **31.5 %**
- **Transfert RF $\rightarrow$ XGBoost : 24.5 %**  
  $\rightarrow$ **Près de 78 %** des attaques réussies sur Random Forest trompent avec succès XGBoost à l'aveugle, démontrant l'existence de faiblesses géométriques communes aux familles d'arbres décisionnels.

---

## 4. Ce qui n'a pas pu être fait et limites méthodologiques

1. **Push distant bloqué par permissions (HTTP 403)** : Le push sur la branche `attacker` a été stoppé proprement par manque de droits d'accès sur le dépôt GitHub de Khouloud (`ameny-dhaouadi` non collaboratrice).
2. **Mode rapide vs Jeu complet** : L'exécution a été menée avec `MAX_ROWS=30000` et `N_ATTACK=200` pour respecter les contraintes de temps calculatoire. Si nécessaire avant le rendu final, le notebook peut être relancé sur les 586 000 lignes du jeu complet sans aucune modification du code source.
3. **Approximation de `reg_domain`** : L'isolation des deux derniers labels du nom d'hôte ne gère pas les extensions composées de la Public Suffix List (ex. `.co.uk`, `.asso.fr`). Dans un cadre industriel, `tldextract` devrait être privilégié.
4. **Hypothèse de score continu** : L'attaque gloutonne exploite la probabilité continue renvoyée par `score()`. Si le détecteur réel ne renvoyait qu'un booléen (*alerte / pas d'alerte*), une attaque par frontière de décision (*HopSkipJump*) serait requise.
5. **Grammaire de mutations** : Les mutations sont limitées aux chemins, requêtes et sous-domaines. Le typosquatting de marque et les homoglyphes en Punycode IDN n'ont pas été explorés.

---

## 5. Prochaines étapes pour Ameny (dans l'ordre)

1. **Contacter Khouloud** : Lui demander d'ajouter le compte GitHub `ameny-dhaouadi` comme collaboratrice avec droits *Write* sur le dépôt `khouloudboumaiza/projet2-ml-d-tection-de-phishing-par-URL`.
2. **Pousser la branche** : Dès que l'invitation est acceptée, taper dans le terminal :
   ```bash
   git push -u origin attacker
   ```
3. **Lancer la Phase 5 (Durcissement)** : Prévenir Khouloud qu'elle peut exécuter la section 5 de son notebook `01_defenseur.ipynb`. Notre module `src/attack.py` implémente rigoureusement l'interface attendue (`set_bounds(S.hi)` et `greedy_attack(det, u, budget)["adv"]`).
4. **Notebook 03 (Évaluation finale conjointe)** : Se réunir avec Khouloud pour rédiger et exécuter `03_final.ipynb` sur le jeu de test final sanctuarisé (comparaison avant/après durcissement sous attaque).

---

## 6. Pour l'oral : Les 8 questions les plus probables

### Q1. Pourquoi avoir choisi une attaque en boîte noire plutôt qu'en boîte blanche ?
> **Réponse** : Dans un scénario réaliste de cybersécurité, un attaquant ne dispose pas des poids ni des hyperparamètres du détecteur de l'organisation ciblée. Il ne peut que soumettre des URL et observer les réponses de l'API. C'est l'hypothèse la plus contraignante et la plus représentative du monde réel.

### Q2. Pourquoi interdire formellement la modification du domaine enregistrable (`reg_domain`) ?
> **Réponse** : Si l'attaquant modifie le domaine enregistrable (par exemple en remplaçant `evil-bank.com` par `paypal.com`), l'URL ne pointe plus vers son serveur malveillant et l'attaque de phishing est vouée à l'échec opérationnel. Le domaine doit rester sous le contrôle de l'attaquant.

### Q3. Pourquoi l'évasion gloutonne plafonne-t-elle dès $B=1$ ou $B=2$ ?
> **Réponse** : XGBoost s'appuie fortement sur des variables de ratio et de comptage (ex. `digit_ratio`, `path_len`, `entropy_url`). L'injection d'un simple paramètre de requête neutre (coût 1) dilue immédiatement ces ratios et fait basculer les coupures des arbres de décision. Les phishing qui résistent à $B=1$ sont bloqués par les caractéristiques intrinsèques de leur nom de domaine, non modifiables.

### Q4. Pourquoi ne mesurer l'évasion que sur les phishing initialement détectés ?
> **Réponse** : Si l'on incluait les faux négatifs initiaux (phishing ayant déjà un score inférieur au seuil), on gonflerait artificiellement le taux de succès sans qu'aucune perturbation adverse n'ait eu lieu. L'évasion doit strictement quantifier la capacité de l'attaquant à inverser une décision d'alerte légitime.

### Q5. Comment garantissez-vous que vos exemples adverses restent réalistes et fonctionnels ?
> **Réponse** : Par quatre verrous automatisés vérifiés sur 100 % des échantillons : préservation du domaine, conformité syntaxique (aucun double `?`, pas de `//`), longueur réaliste ($\le 2000$), et surtout respect des bornes statistiques $S.hi$ (quantile 99,9 % du train) pour interdire toute anomalie volumétrique.

### Q6. Pourquoi l'attaque gloutonne est-elle largement supérieure à l'attaque aléatoire (34 % vs 8 %) ?
> **Réponse** : L'attaque aléatoire effectue une marche aléatoire aveugle sans mémoire de l'objectif, alors que l'attaque gloutonne calcule un gradient empirique boîte noire : elle évalue toutes les mutations valides et sélectionne systématiquement la plus efficace pour faire chuter la probabilité.

### Q7. Comment expliquez-vous le succès de l'attaque par transfert de Random Forest vers XGBoost (24.5 %) ?
> **Réponse** : Bien que leurs algorithmes d'optimisation diffèrent (bagging vs boosting), Random Forest et XGBoost partagent la même famille de séparateurs géométriques (arbres orthogonaux) et découvrent des corrélations similaires sur les variables d'URL. Les failles induites par les variables composites sont donc transverses.

### Q8. Que va-t-il se passer lors du durcissement (réentraînement adverse en Phase 5) ?
> **Réponse** : En réinjectant nos URL modifiées étiquetées en phishing dans le jeu d'entraînement, XGBoost va apprendre à ne plus considérer l'ajout de paramètres bénins ou de sous-domaines comme un certificat de légitimité. Son rappel sous attaque va remonter significativement, potentiellement au prix d'un léger compromis sur le seuil ou les performances bénignes.

