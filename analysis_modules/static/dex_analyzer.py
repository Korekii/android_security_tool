# analysis_modules/static/dex_analyzer.py
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from androguard.core.analysis.analysis import MethodAnalysis
from core.apk_loader import load_apk_with_analysis
from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


class DexAnalyzer(BaseStaticAnalyzer):
    name = "DexAnalyzer"

    # Ключ: (class_name, method_name)
    # class_name в dalvik-формате, например: Landroid/webkit/WebView;
    DANGEROUS_APIS: Dict[Tuple[str, str], Dict] = {
        # Классические
        ("Landroid/telephony/SmsManager;", "sendTextMessage"): {
            "severity": Severity.HIGH,
            "type": "dangerous_api_call",
            "description": "Отправка SMS через SmsManager.sendTextMessage().",
        },
        ("Ljava/lang/Runtime;", "exec"): {
            "severity": Severity.HIGH,
            "type": "dangerous_api_call",
            "description": "Выполнение команд через Runtime.exec().",
        },
        ("Ldalvik/system/DexClassLoader;", "<init>"): {
            "severity": Severity.HIGH,
            "type": "dynamic_code_loading",
            "description": "Динамическая загрузка кода через DexClassLoader.",
        },
        # WebView / JS
        ("Landroid/webkit/WebView;", "loadUrl"): {
            "severity": Severity.MEDIUM,
            "type": "webview_load_url",
            "description": "Загрузка URL в WebView.loadUrl().",
        },
        ("Landroid/webkit/WebView;", "addJavascriptInterface"): {
            "severity": Severity.HIGH,
            "type": "webview_add_js_interface",
            "description": "Добавление JS-интерфейса в WebView.addJavascriptInterface(). "
                           "В сочетании с включённым JavaScript может приводить к RCE.",
        },
        ("Landroid/webkit/WebSettings;", "setJavaScriptEnabled"): {
            "severity": Severity.MEDIUM,
            "type": "webview_js_enabled",
            "description": "Включение JavaScript в WebView через WebSettings.setJavaScriptEnabled().",
        },
        # PendingIntent
        ("Landroid/app/PendingIntent;", "getActivity"): {
            "severity": Severity.MEDIUM,
            "type": "pending_intent_creation",
            "description": "Создание PendingIntent.getActivity(). При неправильных флагах "
                           "может быть подвержено атаке на подмену Intent.",
        },
        ("Landroid/app/PendingIntent;", "getService"): {
            "severity": Severity.MEDIUM,
            "type": "pending_intent_creation",
            "description": "Создание PendingIntent.getService().",
        },
        ("Landroid/app/PendingIntent;", "getBroadcast"): {
            "severity": Severity.MEDIUM,
            "type": "pending_intent_creation",
            "description": "Создание PendingIntent.getBroadcast().",
        },
    }

    # Регексы для поиска хардкоженных секретов
    SECRET_PATTERNS: Dict[str, re.Pattern] = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "jwt_token": re.compile(
            r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+"
        ),
        "private_key": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    }

    # Паттерны потенциально опасных путей (path traversal / внешние dex)
    DANGEROUS_PATH_PATTERNS: Dict[str, re.Pattern] = {
        "external_dex": re.compile(r"/(?:sdcard|storage/emulated|mnt/sdcard)/.+\.dex", re.IGNORECASE),
        "path_traversal": re.compile(r"\.\./"),
    }

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        a, d, dx = load_apk_with_analysis(apk_path)

        findings: List[Threat] = []

        # Флаги для сложных паттернов (например, WebView RCE)
        found_webview_js = False
        found_webview_js_interface = False

        # ---------- Анализ методов ----------
        for method_analysis in dx.get_methods():  # type: MethodAnalysis
            m = getattr(method_analysis, "get_method", None)
            if callable(m):
                m = m()
            else:
                m = getattr(method_analysis, "method", None)
            if m is None:
                continue

            # Пытаемся безопасно достать имя/класс/дескриптор под androguard 3.3.5
            try:
                class_name = m.get_class_name()
            except AttributeError:
                class_name = getattr(m, "class_name", "<unknown>")

            try:
                name = m.get_name()
            except AttributeError:
                name = getattr(m, "name", "<unknown>")

            try:
                descriptor = m.get_descriptor()
            except AttributeError:
                descriptor = getattr(m, "descriptor", "")

            full_name = f"{class_name}->{name}{descriptor}"

            key = (class_name, name)
            api_info = self.DANGEROUS_APIS.get(key)
            if api_info:
                t = Threat(
                    analyzer=self.name,
                    type=api_info["type"],
                    title="Вызов опасного API",
                    description=f"Метод {full_name}: {api_info['description']}",
                    severity=api_info["severity"],
                    location=full_name,
                    metadata={"api_key": key},
                )
                findings.append(t)

                # Отдельно помечаем WebView-case
                if api_info["type"] == "webview_js_enabled":
                    found_webview_js = True
                if api_info["type"] == "webview_add_js_interface":
                    found_webview_js_interface = True

        # Если и JS включён, и JS-интерфейс добавлен — классический WebView RCE-риск
        if found_webview_js and found_webview_js_interface:
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="webview_rce_risk",
                    title="Риск WebView RCE",
                    description=(
                        "В коде приложения обнаружены и WebSettings.setJavaScriptEnabled(true), и "
                        "WebView.addJavascriptInterface(...). В сочетании с загрузкой непроверенного "
                        "контента это может приводить к удалённому выполнению кода через WebView."
                    ),
                    severity=Severity.HIGH,
                    location="classes.dex (WebView)",
                )
            )

        # ---------- Анализ строк на хардкоженные секреты ----------
        for dex in d:
            get_strings = getattr(dex, "get_strings", None)
            if not callable(get_strings):
                continue

            try:
                for s in get_strings():
                    if s is None:
                        continue
                    # s может быть bytes или str
                    if isinstance(s, bytes):
                        try:
                            text = s.decode("utf-8", errors="ignore")
                        except Exception:
                            continue
                    else:
                        text = str(s)

                    for secret_type, pattern in self.SECRET_PATTERNS.items():
                        for match in pattern.findall(text):
                            findings.append(
                                Threat(
                                    analyzer=self.name,
                                    type=f"hardcoded_secret::{secret_type}",
                                    title="Хардкоженный секрет в DEX-строках",
                                    description=(
                                        f"В строках DEX обнаружен возможный секрет типа {secret_type}: {match}. "
                                        "Хранение ключей/токенов в исходниках увеличивает риск компрометации."
                                    ),
                                    severity=Severity.HIGH,
                                    location="classes.dex (string pool)",
                                    metadata={"secret_type": secret_type},
                                )
                            )
            except Exception:
                # Не валим весь анализ из-за одной DEX-ошибки
                continue

        # ---------- Анализ строк на опасные пути / traversal ----------
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

                    for path_type, pattern in self.DANGEROUS_PATH_PATTERNS.items():
                        if pattern.search(text):
                            if path_type == "external_dex":
                                findings.append(
                                    Threat(
                                        analyzer=self.name,
                                        type="dexloader_external_path",
                                        title="DexClassLoader с внешним .dex-путём",
                                        description=(
                                            f"Обнаружена строка с внешним .dex-файлом: {text}. "
                                            "Если этот путь используется в DexClassLoader, "
                                            "злоумышленник может подменить .dex и добиться RCE."
                                        ),
                                        severity=Severity.HIGH,
                                        location="classes.dex (string path)",
                                        metadata={"path": text},
                                    )
                                )
                            elif path_type == "path_traversal":
                                findings.append(
                                    Threat(
                                        analyzer=self.name,
                                        type="path_traversal_risk",
                                        title="Возможный риск path traversal",
                                        description=(
                                            f"Обнаружена строка с последовательностями '../': {text}. "
                                            "Если эта строка используется при формировании файловых путей, "
                                            "возможны атаки directory traversal."
                                        ),
                                        severity=Severity.MEDIUM,
                                        location="classes.dex (string path)",
                                        metadata={"value": text},
                                    )
                                )
            except Exception:
                continue

        for t in findings:
            analysis.add(t)
