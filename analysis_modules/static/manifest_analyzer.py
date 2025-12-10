# analysis_modules/static/manifest_analyzer.py
from __future__ import annotations

from typing import List, Optional, Set

from core.apk_loader import load_apk
from core.models import AnalysisResult, Severity, Threat
from .base import BaseStaticAnalyzer


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _get_android_attr(elem, name: str, default: Optional[str] = None) -> Optional[str]:
    return elem.get(f"{ANDROID_NS}{name}", default)


class ManifestAnalyzer(BaseStaticAnalyzer):
    name = "ManifestAnalyzer"

    # Системные broadcast-action’ы, если receiver на них повешен и открыт — риск injection
    SENSITIVE_BROADCAST_ACTIONS: Set[str] = {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PACKAGE_ADDED",
        "android.provider.Telephony.SMS_RECEIVED",
        "android.intent.action.USER_PRESENT",
        "android.intent.action.BATTERY_CHANGED",
    }

    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        apk = load_apk(apk_path)
        manifest = apk.get_android_manifest_xml()

        # Базовые метаданные
        analysis.package_name = apk.get_package()
        analysis.app_name = apk.get_app_name()
        analysis.version_name = apk.get_androidversion_name()

        findings: List[Threat] = []

        application = manifest.find("application")
        if application is not None:
            # debuggable
            debuggable = _get_android_attr(application, "debuggable")
            if debuggable == "true":
                findings.append(
                    Threat(
                        analyzer=self.name,
                        type="debuggable",
                        title="android:debuggable=\"true\"",
                        description=(
                            "Приложение собрано с флагом android:debuggable=\"true\". "
                            "На продакшене это значительно повышает риск эксплуатации."
                        ),
                        severity=Severity.MEDIUM,
                        location="AndroidManifest.xml: application",
                    )
                )

            # sharedUserId
            shared_user_id = _get_android_attr(application, "sharedUserId")
            if shared_user_id:
                findings.append(
                    Threat(
                        analyzer=self.name,
                        type="shared_user_id",
                        title="Используется android:sharedUserId",
                        description=(
                            f"Приложение использует android:sharedUserId=\"{shared_user_id}\". "
                            "Это может приводить к повышению привилегий при совместной установке "
                            "с другими приложениями с тем же sharedUserId."
                        ),
                        severity=Severity.MEDIUM,
                        location="AndroidManifest.xml: application",
                        metadata={"sharedUserId": shared_user_id},
                    )
                )

        # ---------- Анализ компонентов ----------

        pkg = analysis.package_name or ""

        # Activities
        for activity in manifest.findall(".//activity"):
            self._analyze_activity(activity, pkg, findings)

        # Receivers (broadcast)
        for receiver in manifest.findall(".//receiver"):
            self._analyze_receiver(receiver, pkg, findings)

        # Services
        for service in manifest.findall(".//service"):
            self._analyze_service(service, pkg, findings)

        # ContentProviders
        for provider in manifest.findall(".//provider"):
            self._analyze_provider(provider, pkg, findings)

        for t in findings:
            analysis.add(t)

    # --------- helpers ----------

    def _effective_exported(self, elem) -> bool:
        """
        Простая эвристика "экспортированности" компонента.
        - android:exported="true" -> всегда exported
        - если атрибут не задан, но есть <intent-filter> -> считаем exported
          (Android до 12, targetSdk<31)
        """
        exported_attr = _get_android_attr(elem, "exported")
        if exported_attr == "true":
            return True
        if exported_attr == "false":
            return False
        # Не задан явно
        has_intent_filter = elem.find("intent-filter") is not None
        return has_intent_filter

    def _analyze_activity(self, activity, package_name: str, findings: List[Threat]) -> None:
        name = _get_android_attr(activity, "name") or "<unknown>"
        permission = _get_android_attr(activity, "permission")
        task_affinity = _get_android_attr(activity, "taskAffinity")
        launch_mode = _get_android_attr(activity, "launchMode")
        allow_task_reparenting = _get_android_attr(activity, "allowTaskReparenting")

        exported_effective = self._effective_exported(activity)

        # Экспортированный activity без явного permission — базовый риск
        if exported_effective and not permission:
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="exported_component",
                    title="Экспортированный activity без permission",
                    description=(
                        f"Компонент activity \"{name}\" имеет android:exported=\"true\" "
                        "или неявно экспортирован (intent-filter), но не защищён явным "
                        "разрешением. Это открывает поверхность атаки для других приложений."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: activity {name}",
                    metadata={"component_type": "activity", "name": name},
                )
            )

        # Поиск task hijacking / activity injection
        has_launcher = False
        has_browsable = False
        has_default = False
        for ifilter in activity.findall("intent-filter"):
            for cat in ifilter.findall("category"):
                cat_name = _get_android_attr(cat, "name")
                if cat_name == "android.intent.category.LAUNCHER":
                    has_launcher = True
                if cat_name == "android.intent.category.BROWSABLE":
                    has_browsable = True
                if cat_name == "android.intent.category.DEFAULT":
                    has_default = True

        # Эвристика task hijacking:
        # - exported
        # - есть LAUNCHER или BROWSABLE/DEFAULT
        # - нестандартный taskAffinity / singleTask / singleInstance
        risky_affinity = bool(task_affinity and task_affinity != package_name)
        risky_launch_mode = launch_mode in ("singleTask", "singleInstance")
        if exported_effective and (has_launcher or (has_browsable and has_default)) and (risky_affinity or risky_launch_mode):
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="task_hijacking_risk",
                    title="Риск task hijacking / activity hijacking",
                    description=(
                        f"Activity \"{name}\" экспортирован и имеет intent-filters (LAUNCHER/BROWSABLE/DEFAULT) "
                        f"при нестандартном taskAffinity=\"{task_affinity}\" или launchMode=\"{launch_mode}\". "
                        "Это может позволить злоумышленнику перехватывать задачи или внедряться в back stack."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: activity {name}",
                    metadata={
                        "taskAffinity": task_affinity,
                        "launchMode": launch_mode,
                        "allowTaskReparenting": allow_task_reparenting,
                    },
                )
            )

    def _analyze_receiver(self, receiver, package_name: str, findings: List[Threat]) -> None:
        name = _get_android_attr(receiver, "name") or "<unknown>"
        permission = _get_android_attr(receiver, "permission")
        exported_effective = self._effective_exported(receiver)

        # Экспортированный receiver без permission
        if exported_effective and not permission:
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="exported_receiver",
                    title="Экспортированный BroadcastReceiver без permission",
                    description=(
                        f"BroadcastReceiver \"{name}\" экспортирован и не защищён явным разрешением. "
                        "Это может позволить другим приложениям отправлять в него произвольные broadcast-ы."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: receiver {name}",
                    metadata={"component_type": "receiver", "name": name},
                )
            )

        # Broadcast injection: слушает чувствительные системные action’ы
        if exported_effective:
            for ifilter in receiver.findall("intent-filter"):
                for act in ifilter.findall("action"):
                    act_name = _get_android_attr(act, "name")
                    if act_name in self.SENSITIVE_BROADCAST_ACTIONS and not permission:
                        findings.append(
                            Threat(
                                analyzer=self.name,
                                type="broadcast_injection_risk",
                                title="Риск broadcast injection",
                                description=(
                                    f"Receiver \"{name}\" экспортирован и слушает системный action "
                                    f"\"{act_name}\" без защиты разрешением. Злоумышленник может "
                                    "подделывать такие broadcast-ы."
                                ),
                                severity=Severity.HIGH,
                                location=f"AndroidManifest.xml: receiver {name}",
                                metadata={"action": act_name},
                            )
                        )

    def _analyze_service(self, service, package_name: str, findings: List[Threat]) -> None:
        name = _get_android_attr(service, "name") or "<unknown>"
        permission = _get_android_attr(service, "permission")
        exported_effective = self._effective_exported(service)

        if exported_effective and not permission:
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="exported_service",
                    title="Экспортированный Service без permission",
                    description=(
                        f"Сервис \"{name}\" экспортирован и не защищён явным разрешением. "
                        "Другие приложения могут запускать или связываться с этим сервисом."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: service {name}",
                    metadata={"component_type": "service", "name": name},
                )
            )

    def _analyze_provider(self, provider, package_name: str, findings: List[Threat]) -> None:
        name = _get_android_attr(provider, "name") or "<unknown>"
        permission = _get_android_attr(provider, "permission")
        read_perm = _get_android_attr(provider, "readPermission")
        write_perm = _get_android_attr(provider, "writePermission")
        grant_uri_permissions = _get_android_attr(provider, "grantUriPermissions")
        authorities = _get_android_attr(provider, "authorities")
        exported_effective = self._effective_exported(provider)

        # Полностью открытый провайдер
        if exported_effective and not (permission or read_perm or write_perm):
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="exported_provider",
                    title="Экспортированный ContentProvider без permission",
                    description=(
                        f"ContentProvider \"{name}\" экспортирован и не защищён read/write разрешениями. "
                        "Это может открыть доступ к внутренним данным приложения для других приложений."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: provider {name}",
                    metadata={
                        "component_type": "provider",
                        "name": name,
                        "readPermission": read_perm,
                        "writePermission": write_perm,
                    },
                )
            )

        # Риск traversal / широкого доступа по authorities + grantUriPermissions
        if exported_effective and grant_uri_permissions == "true" and (
                not permission and not (read_perm or write_perm)):
            findings.append(
                Threat(
                    analyzer=self.name,
                    type="provider_uri_grant_risk",
                    title="Риск URI-permission escalation у ContentProvider",
                    description=(
                        f"ContentProvider \"{name}\" экспортирован, имеет grantUriPermissions=\"true\" "
                        "и не защищён явными разрешениями. Это может позволить другим приложениям "
                        "получать временный доступ к данным по произвольным URI."
                    ),
                    severity=Severity.HIGH,
                    location=f"AndroidManifest.xml: provider {name}",
                    metadata={"authorities": authorities, "grantUriPermissions": grant_uri_permissions},
                )
            )

