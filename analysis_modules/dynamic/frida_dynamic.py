# analysis_modules/dynamic/frida_dynamic.py
from __future__ import annotations

import json
import subprocess
import time
from typing import List, Optional

import frida

from core.models import Threat, Severity


DYNAMIC_ANALYZER_NAME = "FridaDynamicAnalyzer"


# ================== ADB helpers ==================

def _run_adb(cmd: list[str], device_id: Optional[str] = None) -> subprocess.CompletedProcess:
    full_cmd = ["adb"]
    if device_id:
        full_cmd += ["-s", device_id]
    full_cmd += cmd
    return subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def install_apk_via_adb(apk_path: str, device_id: Optional[str] = None) -> bool:
    """Установка APK через adb install."""
    proc = _run_adb(["install", "-r", apk_path], device_id=device_id)
    if proc.returncode != 0:
        print(f"[dyn] adb install error: {proc.stderr.strip()}")
        return False
    print(f"[dyn] APK installed: {apk_path}")
    return True


def launch_app_via_adb(package_name: str, device_id: Optional[str] = None) -> None:
    """Запуск приложения через adb shell monkey."""
    proc = _run_adb(["shell", "monkey", "-p", package_name, "-c",
                     "android.intent.category.LAUNCHER", "1"], device_id=device_id)
    if proc.returncode != 0:
        print(f"[dyn] adb launch error: {proc.stderr.strip()}")
    else:
        print(f"[dyn] App launch requested for package: {package_name}")


# ================== Frida script ==================

FRIDA_SCRIPT = r"""
// Frida Java hooks: файловые операции + runtime permissions + sensitive API
Java.perform(function () {
    try {
        // -------- FILE I/O HOOKS --------
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        var FileInputStream = Java.use('java.io.FileInputStream');
        var RandomAccessFile = Java.use('java.io.RandomAccessFile');

        function classifyPath(path) {
            var p = String(path);
            var location = "internal";
            if (p.indexOf("/sdcard") === 0 ||
                p.indexOf("/storage/emulated") === 0 ||
                p.indexOf("/mnt/sdcard") === 0) {
                location = "external";
            }
            return { path: p, location: location };
        }

        // FileOutputStream(File)
        FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
            var info = classifyPath(file.getPath());
            send({
                kind: "file_io",
                op: "write",
                location: info.location,
                path: info.path,
                api: "FileOutputStream(File)"
            });
            return this.$init(file);
        };

        // FileOutputStream(String)
        FileOutputStream.$init.overload('java.lang.String').implementation = function (name) {
            var info = classifyPath(name);
            send({
                kind: "file_io",
                op: "write",
                location: info.location,
                path: info.path,
                api: "FileOutputStream(String)"
            });
            return this.$init(name);
        };

        // FileInputStream(File)
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            var info = classifyPath(file.getPath());
            send({
                kind: "file_io",
                op: "read",
                location: info.location,
                path: info.path,
                api: "FileInputStream(File)"
            });
            return this.$init(file);
        };

        // FileInputStream(String)
        FileInputStream.$init.overload('java.lang.String').implementation = function (name) {
            var info = classifyPath(name);
            send({
                kind: "file_io",
                op: "read",
                location: info.location,
                path: info.path,
                api: "FileInputStream(String)"
            });
            return this.$init(name);
        };

        // RandomAccessFile(File, String mode)
        RandomAccessFile.$init.overload('java.io.File', 'java.lang.String').implementation =
            function (file, mode) {
                var info = classifyPath(file.getPath());
                var op = (String(mode).indexOf("w") !== -1) ? "rw" : "r";
                send({
                    kind: "file_io",
                    op: op,
                    location: info.location,
                    path: info.path,
                    api: "RandomAccessFile(File, String)",
                    mode: String(mode)
                });
                return this.$init(file, mode);
            };

        // RandomAccessFile(String, String mode)
        RandomAccessFile.$init.overload('java.lang.String', 'java.lang.String').implementation =
            function (name, mode) {
                var info = classifyPath(name);
                var op = (String(mode).indexOf("w") !== -1) ? "rw" : "r";
                send({
                    kind: "file_io",
                    op: op,
                    location: info.location,
                    path: info.path,
                    api: "RandomAccessFile(String, String)",
                    mode: String(mode)
                });
                return this.$init(name, mode);
            };

        // -------- RUNTIME PERMISSIONS --------

        try {
            var ActivityCompat = Java.use('androidx.core.app.ActivityCompat');
            ActivityCompat.requestPermissions.overload(
                'android.app.Activity',
                '[Ljava.lang.String;',
                'int'
            ).implementation = function (activity, perms, requestCode) {
                var lst = [];
                for (var i = 0; i < perms.length; i++) {
                    lst.push(String(perms[i]));
                }
                send({
                    kind: "runtime_permission_request",
                    permissions: lst,
                    requestCode: requestCode
                });
                return this.requestPermissions(activity, perms, requestCode);
            };
        } catch (e) {
            // not all apps use androidx ActivityCompat
        }

        try {
            var Activity = Java.use('android.app.Activity');
            Activity.requestPermissions.overload(
                '[Ljava.lang.String;',
                'int'
            ).implementation = function (perms, requestCode) {
                var lst = [];
                for (var i = 0; i < perms.length; i++) {
                    lst.push(String(perms[i]));
                }
                send({
                    kind: "runtime_permission_request",
                    permissions: lst,
                    requestCode: requestCode
                });
                return this.requestPermissions(perms, requestCode);
            };
        } catch (e2) {
            // ignore
        }

        // -------- SENSITIVE APIS --------

        // Location
        try {
            var LocationManager = Java.use('android.location.LocationManager');
            LocationManager.requestLocationUpdates.overload(
                'java.lang.String',
                'long',
                'float',
                'android.location.LocationListener'
            ).implementation = function (provider, minTime, minDistance, listener) {
                send({
                    kind: "sensitive_api",
                    api: "LocationManager.requestLocationUpdates",
                    provider: String(provider),
                    minTime: minTime,
                    minDistance: minDistance
                });
                return this.requestLocationUpdates(provider, minTime, minDistance, listener);
            };
        } catch (e3) {}

        // SMS
        try {
            var SmsManager = Java.use('android.telephony.SmsManager');
            SmsManager.sendTextMessage.overload(
                'java.lang.String',
                'java.lang.String',
                'java.lang.String',
                'android.app.PendingIntent',
                'android.app.PendingIntent'
            ).implementation = function (dest, sca, text, sentPI, deliveryPI) {
                send({
                    kind: "sensitive_api",
                    api: "SmsManager.sendTextMessage",
                    destination: String(dest),
                    textPreview: String(text).substring(0, 50)
                });
                return this.sendTextMessage(dest, sca, text, sentPI, deliveryPI);
            };
        } catch (e4) {}

        // Camera (legacy API)
        try {
            var Camera = Java.use('android.hardware.Camera');
            Camera.open.overload().implementation = function () {
                send({
                    kind: "sensitive_api",
                    api: "Camera.open",
                    details: "Camera opened via legacy API"
                });
                return this.open();
            };
        } catch (e5) {}

        // Microphone / AudioRecord (упрощённо)
        try {
            var AudioRecord = Java.use('android.media.AudioRecord');
            AudioRecord.startRecording.implementation = function () {
                send({
                    kind: "sensitive_api",
                    api: "AudioRecord.startRecording",
                    details: "Audio recording started"
                });
                return this.startRecording();
            };
        } catch (e6) {}

        send({ kind: "frida_status", status: "hooks_attached" });
    } catch (eOuter) {
        send({ kind: "frida_error", error: String(eOuter) });
    }
});
"""


# ================== Dynamic analysis runner ==================

def _severity_for_file_event(location: str, op: str) -> Severity:
    # внешнее хранилище + запись → HIGH, чтение → MEDIUM
    if location == "external":
        if op in ("write", "rw"):
            return Severity.HIGH
        return Severity.MEDIUM
    # внутреннее — INFO/MEDIUM
    if op in ("write", "rw"):
        return Severity.MEDIUM
    return Severity.INFO


def _severity_for_permission(perm: str) -> Severity:
    dangerous_prefixes = (
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    )
    for p in dangerous_prefixes:
        if perm == p:
            return Severity.HIGH
    # прочие runtime-permissions — medium
    return Severity.MEDIUM


def _severity_for_sensitive_api(api: str) -> Severity:
    if "SmsManager.sendTextMessage" in api:
        return Severity.HIGH
    if "LocationManager.requestLocationUpdates" in api:
        return Severity.MEDIUM
    if "Camera.open" in api or "AudioRecord.startRecording" in api:
        return Severity.MEDIUM
    return Severity.INFO


def run_dynamic_analysis_session(
    package_name: str,
    duration: int = 60,
    device_id: Optional[str] = None,
) -> List[Threat]:
    """
    Подключается к приложению через Frida, вешает хуки и
    в течение duration секунд собирает события:
      - файловые операции (FileInput/OutputStream, RandomAccessFile)
      - runtime permissions request
      - чувствительные API (камера, локация, микрофон, SMS)
    Возвращает список Threat.
    """
    threats: List[Threat] = []

    # Получаем устройство
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=10)

    # 🔴 Больше НЕ используем enumerate_applications()
    # Всегда spawn'им процесс по имени пакета
    print(f"[dyn] Spawning {package_name} ...")
    pid = device.spawn([package_name])
    device.resume(pid)
    time.sleep(2)  # дать приложению стартануть

    session = device.attach(pid)
    script = session.create_script(FRIDA_SCRIPT)

    def on_message(message, data):
        if message["type"] != "send":
            return
        payload = message.get("payload") or {}
        kind = payload.get("kind")

        if kind == "frida_status":
            print(f"[dyn] Frida status: {payload.get('status')}")
            return
        if kind == "frida_error":
            print(f"[dyn] Frida error in script: {payload.get('error')}")
            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="frida_script_error",
                    title="Ошибка во Frida-скрипте",
                    description=str(payload.get("error")),
                    severity=Severity.INFO,
                )
            )
            return

        if kind == "file_io":
            path = payload.get("path", "")
            location = payload.get("location", "internal")
            op = payload.get("op", "r")
            api = payload.get("api", "")
            sev = _severity_for_file_event(location, op)

            desc = f"Приложение выполнило файловую операцию '{op}' по пути {path} через {api}."
            if location == "external":
                desc += " Операция во внешнем хранилище (sdcard/storage/emulated)."

            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="dynamic_file_io",
                    title="Файловая операция во время выполнения",
                    description=desc,
                    severity=sev,
                    location=path,
                    metadata={"op": op, "location": location, "api": api},
                )
            )
            return

        if kind == "runtime_permission_request":
            perms = payload.get("permissions", [])
            request_code = payload.get("requestCode")
            for perm in perms:
                sev = _severity_for_permission(perm)
                threats.append(
                    Threat(
                        analyzer=DYNAMIC_ANALYZER_NAME,
                        type="runtime_permission_request",
                        title="Запрос разрешения во время выполнения",
                        description=(
                            f"Приложение запросило разрешение {perm} "
                            f"(requestCode={request_code})."
                        ),
                        severity=sev,
                        metadata={"permission": perm, "requestCode": request_code},
                    )
                )
            return

        if kind == "sensitive_api":
            api_name = payload.get("api", "")
            sev = _severity_for_sensitive_api(api_name)
            desc_parts = [f"Вызван чувствительный API: {api_name}."]
            if "LocationManager.requestLocationUpdates" in api_name:
                desc_parts.append(
                    f" Провайдер: {payload.get('provider')}, "
                    f"minTime={payload.get('minTime')}, "
                    f"minDistance={payload.get('minDistance')}."
                )
            if "SmsManager.sendTextMessage" in api_name:
                desc_parts.append(
                    f" Отправка SMS на {payload.get('destination')}, "
                    f"предпросмотр текста: {payload.get('textPreview')}."
                )
            if "Camera.open" in api_name or "AudioRecord.startRecording" in api_name:
                desc_parts.append(" Это может означать доступ к камере/микрофону.")

            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="sensitive_api_call",
                    title="Вызов чувствительного API во время выполнения",
                    description="".join(desc_parts),
                    severity=sev,
                    metadata=payload,
                )
            )
            return

    script.on("message", on_message)
    script.load()

    print(f"[dyn] Frida hooks attached to {package_name} (pid={pid}), running for {duration} seconds...")
    time.sleep(max(1, duration))

    try:
        session.detach()
    except Exception:
        pass

    print(f"[dyn] Dynamic session finished, collected {len(threats)} events.")
    return threats

