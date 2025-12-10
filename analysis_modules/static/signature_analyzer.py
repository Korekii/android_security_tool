# analyzers/static/signature_analyzer.py
from __future__ import annotations

from typing import List

from core.apk_loader import load_apk
from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


class SignatureAnalyzer(BaseStaticAnalyzer):
    name = "SignatureAnalyzer"

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        apk = load_apk(apk_path)
        findings: List[Threat] = []

        if not apk.is_signed():
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="unsigned_apk",
                    title="APK не подписан",
                    description=(
                        "Приложение не содержит действующей подписи. Такой APK нельзя "
                        "установить на обычное устройство без модификаций, он может быть подделкой."
                    ),
                    severity=Severity.HIGH,
                    location="Подпись APK",
                )
            )
        else:
            if not apk.is_signed_v2() and not apk.is_signed_v3():
                findings.append(
                    Threat(
                        analyzer=self.name,
                        type="legacy_signature",
                        title="Только устаревшая подпись v1",
                        description=(
                            "APK подписан только схемой v1 (JAR-подпись). "
                            "Рекомендуется использовать v2/v3."
                        ),
                        severity=Severity.LOW,
                        location="Подпись APK",
                    )
                )

        for t in findings:
            analysis.add(t)
