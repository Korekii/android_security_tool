# analyzers/static/permissions_analyzer.py
from __future__ import annotations

from typing import Dict, List

from core.apk_loader import load_apk
from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


class PermissionsAnalyzer(BaseStaticAnalyzer):
    name = "PermissionsAnalyzer"

    PERMISSION_RISK: Dict[str, Severity] = {
        "android.permission.SEND_SMS": Severity.HIGH,
        "android.permission.RECEIVE_SMS": Severity.HIGH,
        "android.permission.READ_SMS": Severity.HIGH,
        "android.permission.WRITE_SMS": Severity.HIGH,
        "android.permission.CALL_PHONE": Severity.HIGH,
        "android.permission.READ_CONTACTS": Severity.MEDIUM,
        "android.permission.WRITE_CONTACTS": Severity.MEDIUM,
        "android.permission.RECORD_AUDIO": Severity.MEDIUM,
        "android.permission.CAMERA": Severity.MEDIUM,
        "android.permission.ACCESS_FINE_LOCATION": Severity.MEDIUM,
        "android.permission.ACCESS_COARSE_LOCATION": Severity.MEDIUM,
        "android.permission.READ_CALL_LOG": Severity.MEDIUM,
        "android.permission.WRITE_CALL_LOG": Severity.MEDIUM,
        "android.permission.READ_PHONE_STATE": Severity.MEDIUM,
    }

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        apk = load_apk(apk_path)
        requested_perms = apk.get_permissions()

        findings: List[Threat] = []

        for perm in requested_perms:
            severity = self.PERMISSION_RISK.get(perm)
            if not severity:
                continue

            findings.append(
                Threat(
                    analyzer=self.name,
                    type="dangerous_permission",
                    title=f"Опасное разрешение: {perm}",
                    description=(
                        f"Приложение запрашивает разрешение {perm}. "
                        "Оно относится к повышенному риску и требует проверки контекста использования."
                    ),
                    severity=severity,
                    location="AndroidManifest.xml: uses-permission",
                    metadata={"permission": perm},
                )
            )

        for t in findings:
            analysis.add(t)
