# analysis_modules/static_analysis.py
from __future__ import annotations

from typing import List

from core.models import AnalysisResult, Severity, Threat
from analysis_modules.static.base import BaseStaticAnalyzer
from analysis_modules.static.manifest_analyzer import ManifestAnalyzer
from analysis_modules.static.permissions_analyzer import PermissionsAnalyzer
from analysis_modules.static.dex_analyzer import DexAnalyzer
from analysis_modules.static.resources_analyzer import ResourcesAnalyzer
from analysis_modules.static.signature_analyzer import SignatureAnalyzer
from analysis_modules.static.crypto_analyzer import CryptoAnalyzer
from analysis_modules.static.ml_analyzer import MlAnalyzer

def get_default_static_analyzers() -> List[BaseStaticAnalyzer]:
    return [
        ManifestAnalyzer(),
        PermissionsAnalyzer(),
        DexAnalyzer(),
        ResourcesAnalyzer(),
        SignatureAnalyzer(),
        CryptoAnalyzer(),
        MlAnalyzer(),
    ]


def run_full_static_analysis(apk_path: str) -> AnalysisResult:
    """
    Главный пайплайн статического анализа: прогоняет APK через все анализаторы.
    """
    analysis = AnalysisResult(apk_path=apk_path)
    for analyzer in get_default_static_analyzers():
        try:
            analyzer.analyze(apk_path, analysis)
        except Exception as e:
            analysis.add(
                Threat(
                    analyzer=analyzer.name,
                    type="analyzer_error",
                    title=f"Ошибка в анализаторе {analyzer.name}",
                    description=str(e),
                    severity=Severity.INFO,
                )
            )
    return analysis
