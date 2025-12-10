# analysis_modules/static/__init__.py
from __future__ import annotations

from typing import List

from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .permissions_analyzer import PermissionsAnalyzer
from .dex_analyzer import DexAnalyzer
from .resources_analyzer import ResourcesAnalyzer
from .signature_analyzer import SignatureAnalyzer


def get_default_static_analyzers() -> List[BaseStaticAnalyzer]:
    return [
        ManifestAnalyzer(),
        PermissionsAnalyzer(),
        DexAnalyzer(),
        ResourcesAnalyzer(),
        SignatureAnalyzer(),
    ]


def run_full_static_analysis(apk_path: str) -> AnalysisResult:
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
