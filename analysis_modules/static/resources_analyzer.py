# analysis_modules/static/resources_analyzer.py
from __future__ import annotations

import re
import zipfile
from typing import List, Tuple, Optional
from urllib.parse import urlparse

from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


URL_REGEX = re.compile(
    r"(https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)

IP_CANDIDATE_REGEX = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"
)

IGNORED_URL_PREFIXES = {
    "http://schemas.android.com/apk/res/android",
}

CDN_DOMAINS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
}

TRACKING_DOMAINS = {
    "google-analytics.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "analytics.google.com",
    "app-measurement.com",
    "doubleclick.net",
    "facebook.com",
    "facebook.net",
}

SUSPICIOUS_DOMAINS = {
    "malicious.com",
    "phishing.ru",
}

TELEMETRY_KEYWORDS = {
    "sentry",
    "bugsnag",
    "rollbar",
    "crashlytics",
}

API_KEYWORDS = {
    "api.",
    ".api.",
    "/api/",
}


def _classify_url(url: str) -> Tuple[str, Severity]:
    parsed = urlparse(url)
    host = parsed.netloc.lower()

    if ":" in host:
        host = host.split(":", 1)[0]

    for prefix in IGNORED_URL_PREFIXES:
        if url.startswith(prefix):
            return "android_schema", Severity.INFO

    if host in CDN_DOMAINS:
        return "cdn", Severity.LOW

    if host in TRACKING_DOMAINS:
        return "tracking", Severity.MEDIUM

    for dom in SUSPICIOUS_DOMAINS:
        if dom in host:
            return "suspicious_domain", Severity.HIGH

    for kw in TELEMETRY_KEYWORDS:
        if kw in host:
            return "telemetry", Severity.MEDIUM

    path = (parsed.path or "").lower()
    for kw in API_KEYWORDS:
        if kw in host or kw in path:
            return "api_endpoint", Severity.LOW

    return "generic", Severity.LOW


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        for p in parts:
            if not p.isdigit():
                return False
            v = int(p)
            if v < 0 or v > 255:
                return False
    except ValueError:
        return False
    return True


class ResourcesAnalyzer(BaseStaticAnalyzer):
    name = "ResourcesAnalyzer"

    TEXT_EXTENSIONS = {".xml", ".json", ".html", ".js", ".txt", ".properties"}

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        findings: List[Threat] = []

        seen_urls = set()
        seen_ips = set()

        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                filename = info.filename

                if not any(filename.lower().endswith(ext) for ext in self.TEXT_EXTENSIONS):
                    continue

                try:
                    with zf.open(info, "r") as fp:
                        data = fp.read()
                except Exception:
                    continue

                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for url in URL_REGEX.findall(text):
                    if any(url.startswith(prefix) for prefix in IGNORED_URL_PREFIXES):
                        continue

                    key = (filename, url)
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)

                    category, severity = _classify_url(url)

                    title = "URL в ресурсах"
                    if category == "cdn":
                        title = "CDN-URL в ресурсах"
                    elif category == "tracking":
                        title = "Трекинг-URL в ресурсах"
                    elif category == "telemetry":
                        title = "Телеметрия/краш-репортер в ресурсах"
                    elif category == "api_endpoint":
                        title = "API-эндпоинт в ресурсах"
                    elif category == "suspicious_domain":
                        title = "Подозрительный домен в ресурсах"
                    elif category == "android_schema":
                        title = "Android schema URL"
                    # generic оставляем как есть

                    description = f"В файле {filename} найден URL: {url}"

                    if category == "cdn":
                        description += (
                            " (CDN-провайдер, обычно используется для статики/библиотек)."
                        )
                    elif category == "tracking":
                        description += (
                            " (известный трекинг/аналитика-домен, возможна телеметрия пользователей)."
                        )
                    elif category == "telemetry":
                        description += (
                            " (домен телеметрии/краш-репортинга, приложение может отправлять отчёты)."
                        )
                    elif category == "api_endpoint":
                        description += (
                            " (похоже на API-эндпоинт, запросы могут содержать чувствительные данные)."
                        )
                    elif category == "suspicious_domain":
                        description += (
                            " (домен отмечен как потенциально вредоносный/фишинговый, требует проверки)."
                        )

                    findings.append(
                        Threat(
                            analyzer=self.name,
                            type=f"url_in_resources::{category}",
                            title=title,
                            description=description,
                            severity=severity,
                            location=filename,
                            metadata={"url": url, "category": category},
                        )
                    )

                for ip in IP_CANDIDATE_REGEX.findall(text):
                    if not _is_valid_ipv4(ip):
                        continue

                    key_ip = (filename, ip)
                    if key_ip in seen_ips:
                        continue
                    seen_ips.add(key_ip)

                    findings.append(
                        Threat(
                            analyzer=self.name,
                            type="ip_in_resources",
                            title="IP-адрес в ресурсах",
                            description=(
                                f"В файле {filename} найден IP-адрес: {ip}. "
                                "Жёстко прописанные IP могут указывать на C2-сервер, тестовый хост "
                                "или внутренний сервис, требует ручной проверки."
                            ),
                            severity=Severity.MEDIUM,
                            location=filename,
                            metadata={"ip": ip},
                        )
                    )

        for t in findings:
            analysis.add(t)
