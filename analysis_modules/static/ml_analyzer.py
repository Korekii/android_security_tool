# analysis_modules/static/ml_analyzer.py
from __future__ import annotations

import os
from typing import Dict, List, Set

import joblib

from analysis_modules.static.base import BaseStaticAnalyzer
from core.apk_loader import load_apk_with_analysis
from core.models import AnalysisResult, Severity, Threat

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODELS_DIR = os.path.join(ROOT_DIR, "ml_models")

MODEL_PATH = os.path.join(MODELS_DIR, "android_malware_model.joblib")
COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")


def _extract_permissions(apk) -> Set[str]:
    try:
        return set(apk.get_permissions() or [])
    except Exception:
        return set()


def _extract_components(apk) -> Set[str]:
    comps: Set[str] = set()
    try:
        comps.update(apk.get_activities() or [])
        comps.update(apk.get_services() or [])
        comps.update(apk.get_receivers() or [])
        comps.update(apk.get_providers() or [])
    except Exception:
        pass
    return comps


def _extract_api_calls(dx) -> Set[str]:
    api: Set[str] = set()
    try:
        for m in dx.get_methods():
            try:
                for _, callee, _ in m.get_xref_to():
                    mm = callee.get_method()
                    api.add(f"{mm.get_class_name()}->{mm.get_name()}")
            except Exception:
                continue
    except Exception:
        pass
    return api


def _build_feature_vector(
    feature_columns: List[str],
    permissions: Set[str],
    api_calls: Set[str],
    components: Set[str],
) -> List[int]:
    present = set()

    present |= permissions
    present |= api_calls
    present |= components

    vec = [0] * len(feature_columns)

    for i, col in enumerate(feature_columns):
        if col in present:
            vec[i] = 1
            continue

        if "::" in col:
            suffix = col.split("::", 1)[1]
            if suffix in present:
                vec[i] = 1

    return vec


class MlAnalyzer(BaseStaticAnalyzer):
    name = "MlAnalyzer"

    def __init__(self) -> None:
        self._model = None
        self._columns = None

    def _load(self):
        if self._model is None:
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
            self._model = joblib.load(MODEL_PATH)

        if self._columns is None:
            if not os.path.exists(COLUMNS_PATH):
                raise FileNotFoundError(f"Columns not found: {COLUMNS_PATH}")
            cols = joblib.load(COLUMNS_PATH)
            self._columns = list(cols)

        return self._model, self._columns

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        model, cols = self._load()

        apk, d, dx = load_apk_with_analysis(apk_path)

        perms = _extract_permissions(apk)
        comps = _extract_components(apk)
        apis = _extract_api_calls(dx)

        x_vec = _build_feature_vector(cols, perms, apis, comps)
        X = [x_vec]

        label = "unknown"
        proba = None

        if hasattr(model, "predict"):
            pred = model.predict(X)[0]
            if isinstance(pred, str):
                label = pred
            else:
                label = "malware" if int(pred) == 1 else "benign"

        if hasattr(model, "predict_proba"):
            p = model.predict_proba(X)[0]
            if hasattr(model, "classes_"):
                classes = list(model.classes_)
                if "malware" in classes:
                    proba = float(p[classes.index("malware")])
                elif 1 in classes:
                    proba = float(p[classes.index(1)])
                else:
                    proba = float(max(p))
            else:
                proba = float(max(p))

        if label == "malware" and (proba is None or proba >= 0.85):
            sev = Severity.HIGH
            title = "ML: вероятно вредоносное приложение"
        elif label == "malware" or (proba is not None and proba >= 0.65):
            sev = Severity.MEDIUM
            title = "ML: подозрительное приложение"
        else:
            sev = Severity.INFO
            title = "ML: вероятно безопасное приложение"

        desc = f"ML verdict={label}"
        if proba is not None:
            desc += f", proba_malware={proba:.2%}"

        analysis.add(Threat(
            analyzer=self.name,
            type="ml_verdict",
            title=title,
            description=desc,
            severity=sev,
            metadata={
                "label": label,
                "proba_malware": proba,
                "features_total": len(cols),
                "features_hit": int(sum(x_vec)),
                "model_path": MODEL_PATH,
                "columns_path": COLUMNS_PATH,
            },
        ))
