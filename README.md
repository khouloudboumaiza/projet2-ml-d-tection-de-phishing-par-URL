# Projet 2 : Attaquer son propre détecteur (phishing par URL)

Binôme : **A = Défenseur** : ........ ; **B = Attaquant** : ........

## Objectif
Construire un détecteur de phishing à partir de l'URL (baseline, Random Forest, XGBoost), l'attaquer par évasion avec des modifications d'URL réalistes,
le durcir par entraînement avec exemples adverses, puis mesurer l'effet sur la robustesse et sur la performance normale.

## Qui fait quoi (chaque fichier a un propriétaire)
| Fichier | Propriétaire | Contenu |
|---|---|---|
| `01_defenseur.ipynb` | A | Phases 1, 2 et 5 : données, nettoyage, découpage, audit, modèles, durcissement |
| `src/common.py` | A | Configuration, variables d'URL, métriques, détecteur, sauvegarde de l'état |
| `02_attaquant.ipynb` | B | Phases 3 et 4 + extension (transfert) : modèle de menace, attaque, réalisme |
| `src/attack.py` | B | Opérations autorisées, règles de cohérence, attaques gloutonne et aléatoire |
| `03_final.ipynb` | A + B | Phase 6 : rejeu contre le modèle durci, autres attaques, stabilité, test final |

Branches Git : `defender` (A) et `attacker` (B), fusion dans `main` par pull request relue par l'autre.

## Obtenir les données (non versionnées)
1. Télécharger le jeu *PhiUSIIL Phishing URL* sur la page UCI : https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Placer le CSV dans `data/PhiUSIIL_Phishing_URL_Dataset.csv` (ou changer `DATA_PATH` dans `src/common.py`).
3. Noter la licence indiquée sur la page UCI. Dans ce jeu, `label` = 0 pour phishing, 1 pour légitime (voir `PHISH_VALUE`).

## Lancer (ordre obligatoire)
```
pip install -r requirements.txt
jupyter notebook
```
1. **A** exécute `01_defenseur.ipynb` : après la section 2.2 il écrit `artifacts/` (état partagé). La phase 5 demande `src/attack.py` de B.
2. **B** exécute `02_attaquant.ipynb` (il a besoin de `artifacts/` : soit lancer le 01 lui-même, soit recevoir le dossier de A). Il écrit `results/attaque_gloutonne_avant.csv`.
3. **A + B** : `03_final.ipynb`, par une seule personne, de haut en bas, pour les résultats finaux.

Mode rapide pour tester (quelques minutes) : `MAX_ROWS=30000 N_ATTACK=60 N_TRAIN_ADV=300 TUNE_SAMPLE=8000 jupyter notebook`
(Windows PowerShell : `$env:MAX_ROWS=30000; $env:N_ATTACK=60; $env:N_TRAIN_ADV=300; $env:TUNE_SAMPLE=8000` puis `jupyter notebook`).
Temps indicatif sur le jeu complet : 15 à 40 minutes pour le 01, 5 à 20 pour le 02, 5 à 20 pour le 03.

## Contenu produit
- `figures/` : graphiques (classes, courbes PR, rappel vs amplitude avant/après, test final).
- `results/` : tous les tableaux en CSV.
- `artifacts/` : état partagé entre notebooks (non versionné).

## Reproductibilité
Graine fixée (`SEED = 42`). Découpage par domaine, indices dans `results/split_indices.npz`. Le test n'est utilisé que dans `03_final.ipynb`, section 6.5.
Données publiques uniquement ; aucune attaque contre un système réel : les modifications d'URL sont évaluées sur le modèle, jamais envoyées sur le réseau.


## Détecteur v1 (facile) et v2 (sans raccourcis)
Le profil se choisit avec la variable d'environnement `PROFILE` (avant de lancer le noyau) :

```python
import os; os.environ["PROFILE"] = "v2"   # "v1" = 25 variables d'origine ; "v2" = sans is_https/has_www + 9 variables en plus (défaut)
```
Pour la comparaison : lancer 01, 02, 03 avec `v1`, renommer `results`/`figures` en `results_v1`/`figures_v1` ; relancer avec `v2` (supprimer d'abord `artifacts/`),
renommer en `results_v2`/`figures_v2` ; puis lancer `04_comparaison_v1_v2.ipynb`.
