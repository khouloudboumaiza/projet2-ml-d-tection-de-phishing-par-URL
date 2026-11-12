"""Code commun aux trois notebooks.

Propriétaire : DÉFENSEUR (A). L'attaquant (B) l'utilise mais ne le modifie pas sans prévenir A.
Contient : configuration, variables d'URL, découpage, métriques, détecteur, modèles, sauvegarde de l'état.
"""
import os, re, math, time, random, warnings, collections, json
from types import SimpleNamespace
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (average_precision_score, roc_auc_score, confusion_matrix,
                             precision_score, recall_score, f1_score)
from xgboost import XGBClassifier

try:
    from IPython.display import display
except ImportError:
    display = print

warnings.filterwarnings("ignore")

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------
SEED = 42
random.seed(SEED); np.random.seed(SEED)

DATA_PATH = os.environ.get("DATA_PATH", "data/PhiUSIIL_Phishing_URL_Dataset.csv")
URL_COL, LABEL_COL = "URL", "label"
PHISH_VALUE = 0          # PhiUSIIL : label 0 = phishing, 1 = légitime. VÉRIFIEZ avec quelques URL !
MAX_ROWS = int(os.environ.get("MAX_ROWS", 0)) or None   # None = tout le jeu

THR_FPR = 0.01           # seuil d'alerte : au plus 1 % de faux positifs sur la validation
MAX_QUERIES = 1000       # budget de requêtes par échantillon attaqué (cahier des charges)
BUDGETS = [0, 1, 2, 3, 4, 6, 8, 12]   # amplitude = coût total des modifications autorisées
B_REF = 6                # budget de référence (durcissement, attaque aléatoire, transfert)
N_ATTACK = int(os.environ.get("N_ATTACK", 200))
N_TRAIN_ADV = int(os.environ.get("N_TRAIN_ADV", 1500))
TUNE_SAMPLE = int(os.environ.get("TUNE_SAMPLE", 40000))
TARGET_NAME, SURROGATE_NAME = "xgb", "rf"

ART = "artifacts"        # état partagé entre notebooks (non versionné)
for _d in ["data", "figures", "results", ART]:
    os.makedirs(_d, exist_ok=True)

# --------------------------------------------------------------------------------------
# Variables calculées à partir de la chaîne d'URL
# --------------------------------------------------------------------------------------
SPECIAL = set("!#$%&'*+,;:<>[]{}|\\^~`")

def entropy(s):
    if not s: return 0.0
    c = collections.Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))

def split_url(url):
    return urlsplit(url if "://" in url else "http://" + url)

def reg_domain(url):
    """Domaine enregistrable approché : deux derniers labels (ne gère pas .co.uk : à signaler comme limite)."""
    host = split_url(url).hostname or ""
    if is_ip(host): return host
    return ".".join(host.split(".")[-2:])

SENSITIVE = ["login", "signin", "secure", "verify", "account", "update", "confirm", "password", "bank", "wallet",
             "paypal", "support", "billing", "security", "webscr", "recover", "unlock", "suspend"]
VOWELS = set("aeiou")

def _max_run(s, pred):
    best = cur = 0
    for c in s:
        cur = cur + 1 if pred(c) else 0
        best = max(best, cur)
    return best

def url_features(url):
    sp = split_url(url)
    host = sp.hostname or ""
    ip = is_ip(host)
    labels = host.split(".") if host else []
    n_sub = 0 if ip else max(len(labels) - 2, 0)
    tld = labels[-1] if (labels and not ip) else ""
    path, query = sp.path, sp.query
    n = max(len(url), 1)
    return dict(
        url_len=len(url), host_len=len(host), path_len=len(path), query_len=len(query),
        n_dots=url.count("."), n_sub=n_sub, tld_len=len(tld), is_ip=int(ip),
        is_https=int(sp.scheme == "https"), has_www=int(host.startswith("www.")), has_at=int("@" in url),
        n_hyphen_host=host.count("-"), n_hyphen_url=url.count("-"),
        n_digits_url=sum(c.isdigit() for c in url), n_digits_host=sum(c.isdigit() for c in host),
        n_letters_url=sum(c.isalpha() for c in url), digit_ratio=sum(c.isdigit() for c in url) / n,
        n_slash=url.count("/"), n_path_segments=len([p for p in path.split("/") if p]),
        n_qmark=url.count("?"), n_equal=url.count("="), n_amp=url.count("&"),
        n_percent=url.count("%"), n_special=sum(c in SPECIAL for c in url),
        entropy_url=entropy(url),
        # ---- variables v2 (plus riches : mots sensibles, aspect du nom de domaine) ----
        n_sensitive=sum(url.lower().count(w) for w in SENSITIVE),
        host_entropy=entropy(host),
        host_digit_ratio=sum(c.isdigit() for c in host) / max(len(host), 1),
        max_digit_run=_max_run(url, str.isdigit),
        n_host_tokens=len([t for t in re.split(r"[.\-]", host) if t]),
        max_host_token=max([len(t) for t in re.split(r"[.\-]", host)] + [0]),
        host_vowel_ratio=sum(c in VOWELS for c in host.lower()) / max(sum(c.isalpha() for c in host), 1),
        has_punycode=int("xn--" in host),
        n_path_sensitive=sum(path.lower().count(w) for w in SENSITIVE),
    )

ALL_FEATURES = list(url_features("http://a.b.com/x?y=1").keys())
V2_ONLY = ["n_sensitive", "host_entropy", "host_digit_ratio", "max_digit_run", "n_host_tokens",
           "max_host_token", "host_vowel_ratio", "has_punycode", "n_path_sensitive"]
# PROFILE=v1 : 25 variables d'origine (détecteur « facile », il apprend « http = phishing »).
# PROFILE=v2 : on retire les raccourcis du jeu (is_https, has_www) et on ajoute des variables plus riches.
PROFILE = os.environ.get("PROFILE", "v2")
SHORTCUTS = ["is_https", "has_www"]
if os.environ.get("DROP_FEATURES") is not None:                # surcharge manuelle : DROP_FEATURES="a,b"
    DROP_FEATURES = [f for f in os.environ["DROP_FEATURES"].split(",") if f]
else:
    DROP_FEATURES = SHORTCUTS if PROFILE == "v2" else []
FEATURES = [f for f in ALL_FEATURES if f not in DROP_FEATURES and (PROFILE == "v2" or f not in V2_ONLY)]

def featurize(urls, cols=None):
    return pd.DataFrame([url_features(u) for u in urls], columns=cols or FEATURES).astype(float)

# --------------------------------------------------------------------------------------
# Métriques et seuil
# --------------------------------------------------------------------------------------
def thr_at_fpr(y, s, fpr=THR_FPR):
    """Plus petit seuil laissant au plus `fpr` de légitimes alertés (calculé sur la VALIDATION)."""
    neg = np.sort(s[y == 0])
    k = int(np.ceil((1 - fpr) * len(neg))) - 1
    return float(neg[min(max(k, 0), len(neg) - 1)]) + 1e-9

def metrics_at(y, s, thr):
    pred = (s >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return dict(pr_auc=average_precision_score(y, s), roc_auc=roc_auc_score(y, s),
                precision=precision_score(y, pred, zero_division=0), recall=recall_score(y, pred),
                f1=f1_score(y, pred), fpr=fp / max(fp + tn, 1), tn=tn, fp=fp, fn=fn, tp=tp)

def summary_row(name, y, s, thr):
    r = metrics_at(y, s, thr)
    return dict(modèle=name, **{k: round(v, 4) for k, v in r.items() if k in ("pr_auc", "roc_auc", "precision", "recall", "f1", "fpr")})

# --------------------------------------------------------------------------------------
# Détecteur (ce que l'attaquant voit) et modèles
# --------------------------------------------------------------------------------------
class Detector:
    """Boîte noire : l'attaquant n'utilise que score() / score_F()."""
    def __init__(self, name, model, thr):
        self.name, self.model, self.thr = name, model, thr
    def score_F(self, F):                      # variables déjà calculées
        return self.model.predict_proba(F[FEATURES])[:, 1]
    def score(self, urls):                     # URL brutes
        return self.score_F(featurize(urls))

def make_lr(**p):  return make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED))
def make_rf(**p):  return RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=SEED, **p)
def make_xgb(**p): return XGBClassifier(eval_metric="logloss", tree_method="hist", n_jobs=-1, random_state=SEED, **p)
BUILDERS = {"lr": make_lr, "rf": make_rf, "xgb": make_xgb}

GRIDS = {
    "rf":  {"max_depth": [None, 12, 20], "min_samples_leaf": [1, 2, 5], "max_features": ["sqrt", 0.5]},
    "xgb": {"n_estimators": [200, 400], "max_depth": [4, 6, 8], "learning_rate": [0.05, 0.1, 0.2], "subsample": [0.8, 1.0]},
}

def sample_phish(urls, y, n, seed):
    idx = np.where(y == 1)[0]
    return urls[np.random.default_rng(seed).choice(idx, size=min(n, len(idx)), replace=False)]

# --------------------------------------------------------------------------------------
# État partagé : jeux découpés + sauvegarde / chargement entre notebooks
# --------------------------------------------------------------------------------------
def make_state(df, train_idx, val_idx, test_idx, X_all=None):
    """df : colonnes url_norm, y, domain. Retourne un objet S avec tous les jeux."""
    if X_all is None:
        X_all = featurize(df["url_norm"])
    y, g, u = df["y"].values, df["domain"].values, df["url_norm"].values
    S = SimpleNamespace(df=df, X_all=X_all, train_idx=train_idx, val_idx=val_idx, test_idx=test_idx)
    for nm, idx in (("train", train_idx), ("val", val_idx), ("test", test_idx)):
        setattr(S, "X_" + nm, X_all.iloc[idx]); setattr(S, "y_" + nm, y[idx])
        setattr(S, "g_" + nm, g[idx]);          setattr(S, "urls_" + nm, u[idx])
    S.hi = S.X_train[FEATURES].quantile(0.999)      # bornes de plausibilité (apprises sur le train)
    return S

def save_state(S):
    S.df.to_csv(f"{ART}/clean.csv.gz", index=False)
    np.savez(f"{ART}/split_indices.npz", train=S.train_idx, val=S.val_idx, test=S.test_idx)
    np.savez("results/split_indices.npz", train=S.train_idx, val=S.val_idx, test=S.test_idx)

def load_state():
    if not os.path.exists(f"{ART}/clean.csv.gz"):
        raise FileNotFoundError("artifacts/clean.csv.gz introuvable : lancez d'abord le notebook 01_defenseur (sections 1.1 à 1.4).")
    df = pd.read_csv(f"{ART}/clean.csv.gz")
    sp = np.load(f"{ART}/split_indices.npz")
    return make_state(df, sp["train"], sp["val"], sp["test"])

def save_detectors(models, thr, best):
    joblib.dump({"models": models, "thr": thr, "best": best}, f"{ART}/detectors.joblib")

def load_detectors():
    if not os.path.exists(f"{ART}/detectors.joblib"):
        raise FileNotFoundError("artifacts/detectors.joblib introuvable : lancez d'abord le notebook 01_defenseur (jusqu'à la section 2.3).")
    d = joblib.load(f"{ART}/detectors.joblib")
    return {n: Detector(n, d["models"][n], d["thr"][n]) for n in d["models"]}, d["best"]

def save_hardened(det):
    joblib.dump({"name": det.name, "model": det.model, "thr": det.thr}, f"{ART}/hardened.joblib")

def load_hardened():
    if not os.path.exists(f"{ART}/hardened.joblib"):
        raise FileNotFoundError("artifacts/hardened.joblib introuvable : lancez d'abord la phase 5 du notebook 01_defenseur.")
    d = joblib.load(f"{ART}/hardened.joblib")
    return Detector(d["name"], d["model"], d["thr"])
