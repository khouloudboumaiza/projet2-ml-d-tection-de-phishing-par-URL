"""Attaque boîte noire sur détecteur de phishing par URL.

Auteur : Ameny Dhouady (Attaquante - Personne B)
Défenseur : Khouloud Boumaiza (Personne A)

Ce module implémente :
1. Le modèle de menace en boîte noire (seul le score de probabilité est accessible).
2. Les opérations de mutation d'URL réalistes avec leurs coûts entiers associés.
3. Les règles strictes de cohérence et de plausibilité (is_valid).
4. L'algorithme d'attaque gloutonne (greedy_attack).
5. L'algorithme d'attaque aléatoire (random_attack).
"""

import re
import random
from urllib.parse import urlsplit, urlunsplit
import numpy as np

from src.common import (
    SEED, MAX_QUERIES, FEATURES, SENSITIVE,
    split_url, reg_domain, featurize, is_ip
)

# Variable de module stockant les bornes de plausibilité (quantile 99.9% du train)
BOUNDS = None

def set_bounds(hi):
    """Mémorise les bornes de plausibilité issues du jeu d'entraînement.
    
    Paramètre :
        hi (pd.Series ou dict) : bornes supérieures (quantile 99,9 %) de chaque variable.
    """
    global BOUNDS
    BOUNDS = hi


def is_valid_structure(orig, adv):
    """Contrôle rapide de la cohérence structurelle et syntaxique de l'URL candidate.
    
    Règles vérifiées :
    1. Longueur plausible (<= 2000 caractères, > 0).
    2. Pas d'espaces ni retours à la ligne.
    3. Au plus un '?' (délimiteur query).
    4. Schéma préservé (http ou https identique à l'original).
    5. Hôte non vide et parsable.
    6. Domaine enregistrable STRICTEMENT identique (reg_domain).
    7. Pas de double slash anomalique dans le chemin.
    """
    if not adv or len(adv) > 2000 or len(adv) == 0:
        return False
    if any(c in adv for c in " \t\r\n"):
        return False
    if adv.count("?") > 1:
        return False
        
    try:
        sp_orig = split_url(orig)
        sp_adv = split_url(adv)
    except Exception:
        return False
        
    if sp_orig.scheme != sp_adv.scheme:
        return False
    if not sp_adv.netloc or not sp_adv.hostname:
        return False
    if reg_domain(adv) != reg_domain(orig):
        return False
    if "//" in sp_adv.path:
        return False
        
    return True


def is_valid(orig, adv):
    """Vérifie la cohérence structurelle, sémantique et la plausibilité statistique de l'URL adverse.
    
    Règles vérifiées :
    1. Préservation stricte du domaine enregistrable (reg_domain) pour ne pas détruire le phishing.
    2. Parsabilité correcte de l'URL et conservation du schéma (http/https).
    3. Absence d'anomalies syntaxiques grossières (au plus un '?', pas d'espaces, pas de '//' injustifié).
    4. Longueur maximale plausible (<= 2000 caractères).
    5. Respect des bornes de plausibilité statistiques (toutes les variables <= BOUNDS).
    """
    if not is_valid_structure(orig, adv):
        return False
        
    if BOUNDS is not None:
        try:
            f_adv = featurize([adv])
            for col in FEATURES:
                if col in BOUNDS:
                    if f_adv[col].iloc[0] > BOUNDS[col]:
                        return False
        except Exception:
            return False

    return True


# --------------------------------------------------------------------------------------
# Opérations autorisées de mutation d'URL et coûts
# --------------------------------------------------------------------------------------
# Coûts :
# - Coût 1 : Ajout de paramètre de requête (libre, ignoré par le serveur cible, impacte l'entropie/longueur)
# - Coût 1 : Ajout d'un segment de chemin neutre (facilement routable par reverse-proxy ou mod_rewrite)
# - Coût 1 : Ajout de tirets ou chiffres dans le chemin (léger ajustement de route)
# - Coût 2 : Retrait d'un mot sensible du chemin (demande une modification de structure/ingénierie sociale)
# - Coût 2 : Ajout d'un sous-domaine (nécessite une entrée DNS CNAME/A supplémentaire)

QUERY_CANDIDATES = [
    ("ref", "home"), ("lang", "en"), ("view", "main"), ("id", "1024"),
    ("utm_source", "portal"), ("q", "search"), ("page", "1"), ("mode", "view"),
    ("tab", "all"), ("v", "2"), ("src", "web"), ("type", "user")
]

PATH_SEGMENTS = [
    "en", "index", "web", "home", "portal", "app", "v1", "main", "static", "user"
]

PATH_SUFFIXES = [
    "-1", "-2024", "-ref", "-doc", "-item", "01", "2"
]

SUBDOMAINS = [
    "portal", "mail", "cdn", "api", "srv1", "static", "m", "auth", "login", "my", "web"
]

def generate_candidates(url, budget_left):
    """Génère tous les candidats accessibles en une seule opération coûtant <= budget_left.
    
    Retourne une liste de tuples (cand_url, cost, op_name).
    """
    cands = []
    sp = split_url(url)
    scheme, netloc, path, query, fragment = sp.scheme, sp.netloc, sp.path, sp.query, sp.fragment
    
    # ------------------------------------------------------------------
    # 1. Opérations à COÛT 1
    # ------------------------------------------------------------------
    if budget_left >= 1:
        # A. Ajout de paramètres de requête
        for k, v in QUERY_CANDIDATES:
            pair = f"{k}={v}"
            if not query:
                new_query = pair
            else:
                if pair in query:
                    continue
                new_query = f"{query}&{pair}"
            new_url = urlunsplit((scheme, netloc, path, new_query, fragment))
            cands.append((new_url, 1, f"add_query_{k}={v}"))
            
        # B. Ajout de segments de chemin neutres
        clean_path = path.rstrip("/")
        for seg in PATH_SEGMENTS:
            p1 = f"/{seg}{path}" if path.startswith("/") else f"/{seg}/{path}"
            new_url1 = urlunsplit((scheme, netloc, p1, query, fragment))
            cands.append((new_url1, 1, f"add_path_prefix_{seg}"))
            
            p2 = f"{clean_path}/{seg}" if clean_path else f"/{seg}"
            new_url2 = urlunsplit((scheme, netloc, p2, query, fragment))
            cands.append((new_url2, 1, f"add_path_suffix_{seg}"))
            
        # C. Ajout de tirets ou chiffres dans le chemin
        if path and path != "/":
            parts = [p for p in path.split("/") if p]
            if parts:
                for suf in PATH_SUFFIXES:
                    new_parts = list(parts)
                    new_parts[-1] = f"{parts[-1]}{suf}"
                    p3 = "/" + "/".join(new_parts)
                    new_url3 = urlunsplit((scheme, netloc, p3, query, fragment))
                    cands.append((new_url3, 1, f"add_path_token_{suf}"))

    # ------------------------------------------------------------------
    # 2. Opérations à COÛT 2
    # ------------------------------------------------------------------
    if budget_left >= 2:
        # D. Retrait ou substitution d'un mot sensible dans le chemin
        path_lower = path.lower()
        for w in SENSITIVE:
            if w in path_lower:
                p_rem = re.sub(re.escape(w), "", path, flags=re.IGNORECASE)
                p_rem = re.sub(r"/+", "/", p_rem)
                if not p_rem.startswith("/"):
                    p_rem = "/" + p_rem
                new_url_rem = urlunsplit((scheme, netloc, p_rem, query, fragment))
                cands.append((new_url_rem, 2, f"remove_sensitive_{w}"))
                
                p_sub = re.sub(re.escape(w), "dir", path, count=1, flags=re.IGNORECASE)
                new_url_sub = urlunsplit((scheme, netloc, p_sub, query, fragment))
                cands.append((new_url_sub, 2, f"substitute_sensitive_{w}"))
                
        # E. Ajout d'un sous-domaine (seulement si l'hôte n'est pas une adresse IP)
        host = sp.hostname or ""
        port = f":{sp.port}" if sp.port else ""
        if host and not is_ip(host):
            for sub in SUBDOMAINS:
                if not host.startswith(f"{sub}."):
                    new_netloc = f"{sub}.{host}{port}"
                    new_url_subd = urlunsplit((scheme, new_netloc, path, query, fragment))
                    cands.append((new_url_subd, 2, f"add_subdomain_{sub}"))

    return cands


# --------------------------------------------------------------------------------------
# Attaque Gloutonne (Greedy Attack)
# --------------------------------------------------------------------------------------
def greedy_attack(det, url, budget):
    """Exécute une attaque gloutonne en boîte noire pour faire évader l'URL de phishing.
    
    À chaque étape :
    1. Génère les candidats pour les opérations dont le coût <= budget restant.
    2. Filtre les candidats via cohérence structurelle et respect des bornes S.hi.
    3. Évalue tous les candidats valides en un appel vectorisé `det.score()`.
    4. Sélectionne le candidat minimisant le score.
    5. S'arrête dès que score < det.thr (succès), budget épuisé, MAX_QUERIES atteint,
       ou aucun candidat n'améliore le score.
       
    Retourne :
        dict avec clés: "adv", "score0", "score", "cost", "queries", "evaded", "ops"
    """
    initial_score = float(det.score([url])[0])
    queries_used = 1
    
    # Si déjà non détecté au départ
    if initial_score < det.thr:
        return {
            "adv": url,
            "score0": initial_score,
            "score": initial_score,
            "cost": 0,
            "queries": queries_used,
            "evaded": True,
            "ops": []
        }
        
    cur_url = url
    cur_score = initial_score
    budget_left = budget
    cost_spent = 0
    ops_applied = []
    
    while budget_left > 0 and queries_used < MAX_QUERIES:
        raw_cands = generate_candidates(cur_url, budget_left)
        if not raw_cands:
            break
            
        # Filtrage structurel rapide et déduplication
        seen = {cur_url, url}
        struct_valid = []
        for c_url, c_cost, c_op in raw_cands:
            if c_url not in seen and is_valid_structure(url, c_url):
                seen.add(c_url)
                struct_valid.append((c_url, c_cost, c_op))
                
        if not struct_valid:
            break
            
        # Limite au budget global de requêtes
        max_batch = MAX_QUERIES - queries_used
        if len(struct_valid) > max_batch:
            struct_valid = struct_valid[:max_batch]
            
        cand_urls = [c[0] for c in struct_valid]
        F_cands = featurize(cand_urls)
        
        # Filtrage par bornes de plausibilité statistiques (vectorisé)
        if BOUNDS is not None:
            mask_bounds = (F_cands[FEATURES].values <= BOUNDS[FEATURES].values).all(axis=1)
            valid_indices = np.where(mask_bounds)[0]
        else:
            valid_indices = np.arange(len(cand_urls))
            
        if len(valid_indices) == 0:
            break
            
        valid_cands = [struct_valid[i] for i in valid_indices]
        F_valid = F_cands.iloc[valid_indices]
        
        # Évaluation vectorisée
        scores = det.score_F(F_valid)
        queries_used += len(valid_cands)
        
        # Trouver la meilleure amélioration
        best_idx = int(scores.argmin())
        best_score = float(scores[best_idx])
        best_cand_url, best_cost, best_op = valid_cands[best_idx]
        
        # Amélioration stricte requise
        if best_score < cur_score:
            cur_url = best_cand_url
            cur_score = best_score
            budget_left -= best_cost
            cost_spent += best_cost
            ops_applied.append(best_op)
            
            # Évasion réussie !
            if cur_score < det.thr:
                return {
                    "adv": cur_url,
                    "score0": initial_score,
                    "score": cur_score,
                    "cost": cost_spent,
                    "queries": queries_used,
                    "evaded": True,
                    "ops": ops_applied
                }
        else:
            # Aucun candidat n'améliore le score : minimum local atteint
            break
            
    evaded = cur_score < det.thr
    return {
        "adv": cur_url if evaded else url,
        "score0": initial_score,
        "score": cur_score,
        "cost": cost_spent if evaded else 0,
        "queries": queries_used,
        "evaded": evaded,
        "ops": ops_applied if evaded else []
    }


# --------------------------------------------------------------------------------------
# Attaque Aléatoire (Random Attack)
# --------------------------------------------------------------------------------------
def random_attack(det, url, budget, seed=SEED):
    """Exécute une attaque aléatoire (baseline) dans les mêmes contraintes de coût et requêtes.
    
    À chaque étape :
    1. Génère les candidats valides pour les opérations dont le coût <= budget restant.
    2. Tire un candidat aléatoirement avec une graine fixée.
    3. Évalue ce candidat unique (`queries += 1`).
    4. L'applique et poursuit jusqu'à évasion, épuisement du budget ou MAX_QUERIES.
       
    Retourne :
        dict au même format que greedy_attack.
    """
    rng = random.Random(seed)
    initial_score = float(det.score([url])[0])
    queries_used = 1
    
    if initial_score < det.thr:
        return {
            "adv": url,
            "score0": initial_score,
            "score": initial_score,
            "cost": 0,
            "queries": queries_used,
            "evaded": True,
            "ops": []
        }
        
    cur_url = url
    cur_score = initial_score
    budget_left = budget
    cost_spent = 0
    ops_applied = []
    
    while budget_left > 0 and queries_used < MAX_QUERIES:
        raw_cands = generate_candidates(cur_url, budget_left)
        if not raw_cands:
            break
            
        struct_cands = [c for c in raw_cands if is_valid_structure(url, c[0]) and c[0] != cur_url]
        if not struct_cands:
            break
            
        # Sélection aléatoire rapide : on mélange et on prend le premier vérifiant is_valid
        rng.shuffle(struct_cands)
        chosen = None
        for c in struct_cands:
            if is_valid(url, c[0]):
                chosen = c
                break
                
        if chosen is None:
            break
            
        c_url, c_cost, c_op = chosen
        score = float(det.score([c_url])[0])
        queries_used += 1
        
        cur_url = c_url
        cur_score = score
        budget_left -= c_cost
        cost_spent += c_cost
        ops_applied.append(c_op)
        
        if cur_score < det.thr:
            return {
                "adv": cur_url,
                "score0": initial_score,
                "score": cur_score,
                "cost": cost_spent,
                "queries": queries_used,
                "evaded": True,
                "ops": ops_applied
            }
            
    evaded = cur_score < det.thr
    return {
        "adv": cur_url if evaded else url,
        "score0": initial_score,
        "score": cur_score,
        "cost": cost_spent if evaded else 0,
        "queries": queries_used,
        "evaded": evaded,
        "ops": ops_applied if evaded else []
    }


if __name__ == "__main__":
    print("Test unitaire rapide de src/attack.py...")
    u_test = "http://secure-login.paypal.com.phish-bank.com/login/verify.php?session=1"
    assert is_valid(u_test, u_test)
    print("URL test:", u_test)
    print("Domaine enregistrable:", reg_domain(u_test))
    cands = generate_candidates(u_test, budget_left=6)
    print(f"Candidats générés (budget 6) : {len(cands)}")
    valid_cands = [c for c in cands if is_valid(u_test, c[0])]
    print(f"Candidats valides : {len(valid_cands)}")
    assert len(valid_cands) > 0, "Au moins un candidat valide doit être produit !"
    print("Module src/attack.py validé avec succès.")
