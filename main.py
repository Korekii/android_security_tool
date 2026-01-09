# main.py
import argparse
import os
from typing import List
from core.models import AnalysisResult

from analysis_modules.static_analysis import run_full_static_analysis

from core.models import Severity, Threat
from reports.pdf_report import generate_pdf_report


def print_threats(threats: List[Threat]) -> None:
    for t in threats:
        print(f"[{t.severity}] {t.analyzer}::{t.type} - {t.title}")
        if t.location:
            print(f"  location: {t.location}")
        print(f"  {t.description}")
        if t.metadata:
            print(f"  metadata: {t.metadata}")
        print()


def cmd_scan_apk(apk_path: str, pdf_path: str | None = None) -> None:
    import os
    if not os.path.isfile(apk_path):
        print(f"Файл APK не найден: {apk_path}")
        return

    analysis = run_full_static_analysis(apk_path)

    print("==== Общая информация ====")
    print(f"APK:        {apk_path}")
    print(f"Пакет:      {analysis.package_name}")
    print(f"Название:   {analysis.app_name}")
    print(f"Версия:     {analysis.version_name}")
    print(f"Находок:    {len(analysis.findings)}")
    print(f"Риск-score: {analysis.risk_score()} (grade {analysis.risk_grade()})")
    print()

    print("==== Найденные проблемы ====")
    for t in analysis.findings:
        print(f"[{t.severity}] {t.analyzer}::{t.type} - {t.title}")
        if t.location:
            print(f"  location: {t.location}")
        print(f"  {t.description}")
        if t.metadata:
            print(f"  metadata: {t.metadata}")
        print()

    if pdf_path:
        try:
            generate_pdf_report(analysis, pdf_path, title="Android Static Analysis Report",)
            print(f"PDF-отчёт сохранён в: {pdf_path}")
        except Exception as e:
            print(f"Не удалось создать PDF-отчёт: {e}")


def simple_logger(msg: str, level: str = "info") -> None:
    print(f"[{level.upper()}] {msg}")


def cmd_dynamic(
    package: str,
    duration: int,
    apk_path: str | None = None,
    device_id: str | None = None,
    pdf_path: str | None = None,
) -> None:
    from analysis_modules.dynamic.frida_dynamic import (
        run_dynamic_analysis_session,
        install_apk_via_adb,
        launch_app_via_adb,
    )

    if apk_path:
        if not os.path.isfile(apk_path):
            print(f"APK не найден: {apk_path}")
            return
        ok = install_apk_via_adb(apk_path, device_id=device_id)
        if not ok:
            return



    print(f"[dyn] Запуск динамического анализа для {package}, {duration} секунд...")
    threats = run_dynamic_analysis_session(
        package_name=package,
        duration=duration,
        device_id=device_id,
    )

    print(f"[dyn] Событий собрано: {len(threats)}")
    print("==== Dynamic findings ====")
    for t in threats:
        print(f"[{t.severity}] {t.analyzer}::{t.type} - {t.title}")
        if t.location:
            print(f"  location: {t.location}")
        print(f"  {t.description}")
        if t.metadata:
            print(f"  metadata: {t.metadata}")
        print()

    if pdf_path:

        from core.apk_loader import load_apk

        app_name = None
        version_name = None

        if apk_path:
            try:
                apk_obj = load_apk(apk_path)

                try:
                    version_name = apk_obj.get_androidversion_name()
                except Exception:
                    version_name = None

                try:
                    app_name = apk_obj.get_app_name()
                except Exception:
                    app_name = None

            except Exception as e:
                print(f"[dyn] Не удалось прочитать метаданные APK через androguard: {e}")

        analysis = AnalysisResult(
            apk_path=apk_path or f"<runtime:{package}>",
            package_name=package,
            app_name=app_name,
            version_name=version_name,
        )
        analysis.extend(threats)
        try:
            generate_pdf_report(analysis, pdf_path, title="Android Dynamic Analysis Report",)
            print(f"[dyn] PDF-отчёт по динамическому анализу сохранён в: {pdf_path}")
        except Exception as e:
            print(f"[dyn] Не удалось создать PDF-отчёт по динамике: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Лёгкий Android-анализатор: статический + динамический (Frida + ADB)."
    )
    subparsers = parser.add_subparsers(dest="command")

    p_scan = subparsers.add_parser("scan-apk", help="Выполнить статический анализ APK")
    p_scan.add_argument("apk", help="Путь к APK-файлу")
    p_scan.add_argument(
        "--pdf",
        dest="pdf",
        help="Путь для сохранения PDF-отчёта"
    )

    p_dyn = subparsers.add_parser("dyn", help="Выполнить динамический анализ приложения")
    p_dyn.add_argument("package", help="Имя пакета (например, com.example.app)")
    p_dyn.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Длительность сессии динамического анализа (секунды)",
    )
    p_dyn.add_argument(
        "--apk",
        dest="apk",
        help="Путь к APK для установки перед анализом (опционально)",
    )
    p_dyn.add_argument(
        "--device",
        dest="device",
        help="ID устройства (из adb devices). Если не задан, используется USB-девайс по умолчанию.",
    )
    p_dyn.add_argument(
        "--pdf",
        dest="pdf",
        help="Путь для сохранения PDF-отчёта по динамическому анализу",
    )

    args = parser.parse_args()

    if args.command == "scan-apk":
        cmd_scan_apk(args.apk, pdf_path=args.pdf)
    elif args.command == "dyn":
        cmd_dynamic(
            package=args.package,
            duration=args.duration,
            apk_path=args.apk,
            device_id=args.device,
            pdf_path=args.pdf,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
