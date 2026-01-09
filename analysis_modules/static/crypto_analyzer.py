from __future__ import annotations

import re
from typing import List

from core.apk_loader import load_apk_with_analysis
from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


class CryptoAnalyzer(BaseStaticAnalyzer):
    name = "CryptoAnalyzer"

    WEAK_CRYPTO_PATTERNS = {
        "md5": {
            "regex": re.compile(r"\bMD5\b", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "description": "Используется хеш-функция MD5, которая считается криптографически ненадёжной.",
        },
        "sha1": {
            "regex": re.compile(r"\bSHA-?1\b", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "description": "Используется SHA1, устаревшая и уязвимая к коллизиям.",
        },
        "aes_ecb": {
            "regex": re.compile(r"AES/ECB", re.IGNORECASE),
            "severity": Severity.HIGH,
            "description": "Используется режим шифрования AES/ECB. ECB не обеспечивает семантическую безопасность.",
        },
        "des": {
            "regex": re.compile(r"\bDES(?!EDE)\b", re.IGNORECASE),
            "severity": Severity.HIGH,
            "description": "Используется DES, который считается небезопасным из-за короткого ключа.",
        },
        "rc4": {
            "regex": re.compile(r"\bRC4\b", re.IGNORECASE),
            "severity": Severity.HIGH,
            "description": "Используется потоковый шифр RC4, считающийся небезопасным.",
        },
    }

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        a, d, dx = load_apk_with_analysis(apk_path)

        findings: List[Threat] = []
        seen = set()

        for dex in d:
            get_strings = getattr(dex, "get_strings", None)
            if not callable(get_strings):
                continue

            try:
                for s in get_strings():
                    if s is None:
                        continue

                    if isinstance(s, bytes):
                        try:
                            text = s.decode("utf-8", errors="ignore")
                        except Exception:
                            continue
                    else:
                        text = str(s)

                    for key, info in self.WEAK_CRYPTO_PATTERNS.items():
                        if info["regex"].search(text):
                            if (key, text) in seen:
                                continue
                            seen.add((key, text))

                            findings.append(
                                Threat(
                                    analyzer=self.name,
                                    type=f"weak_crypto::{key}",
                                    title="Небезопасная криптография",
                                    description=f"Обнаружена потенциально небезопасная крипто-конструкция: \"{text}\". "
                                                f"{info['description']}",
                                    severity=info["severity"],
                                    location="classes.dex (crypto strings)",
                                    metadata={"pattern_type": key, "value": text},
                                )
                            )
            except Exception:
                continue

        for t in findings:
            analysis.add(t)
