# analysis_modules/dynamic/frida_dynamic.py
from __future__ import annotations

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
    proc = _run_adb(
        ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        device_id=device_id,
    )
    if proc.returncode != 0:
        print(f"[dyn] adb launch error: {proc.stderr.strip()}")
    else:
        print(f"[dyn] App launch requested for package: {package_name}")


# ================== Frida script (native) ==================

FRIDA_SCRIPT = r"""
(function () {
  // Всегда даём признаки жизни
  send({ kind: "frida_status", status: "script_loaded_native" });
  send({kind:"frida_status", status: (Java && Java.available) ? "java_available" : "java_not_available"});

  function ptrToString(p) {
    try { return Memory.readCString(p); } catch (e) { return "<unreadable>"; }
  }

  function classifyPath(path) {
    if (!path) return "unknown";
    if (path.indexOf("/sdcard") === 0 ||
        path.indexOf("/storage/emulated") === 0 ||
        path.indexOf("/mnt/sdcard") === 0) return "external";
    if (path.indexOf("/data/data") === 0) return "internal";
    return "other";
  }

  // Важно: ищем символы в libc.so, а не через null
  function hookExport(name, onEnterFn, onLeaveFn) {
    var addr = null;

    try {
      addr = Module.findExportByName("libc.so", name);
    } catch (e) {}

    if (!addr) {
      try { addr = Module.findExportByName(null, name); } catch (e2) {}
    }

    if (!addr) {
      send({ kind: "frida_status", status: "hook_missing", hook: name });
      return false;
    }

    Interceptor.attach(addr, {
      onEnter: function (args) { if (onEnterFn) onEnterFn.call(this, args); },
      onLeave: function (retval) { if (onLeaveFn) onLeaveFn.call(this, retval); }
    });

    send({ kind: "frida_status", status: "hook_ok", hook: name });
    return true;
  }

  // -------------------------
  // FILE I/O (libc)
  // -------------------------

  // Android часто использует openat64/open64/__openat64, поэтому хукаем набор вариантов
  ["open", "open64", "openat", "openat64", "__openat", "__openat64"].forEach(function (fn) {
    hookExport(fn, function (args) {
      var pathPtr = (fn.indexOf("openat") !== -1) ? args[1] : args[0];
      var path = ptrToString(pathPtr);

      send({
        kind: "file_io",
        op: fn,
        path: path,
        location: classifyPath(path),
        api: "libc." + fn
      });
    });
  });

  // read/write — полезны и для файлов, и для сокетов
  hookExport("read", function (args) {
    send({
      kind: "file_io",
      op: "read",
      fd: args[0].toInt32(),
      count: args[2].toInt32(),
      api: "libc.read"
    });
  });

  hookExport("write", function (args) {
    send({
      kind: "file_io",
      op: "write",
      fd: args[0].toInt32(),
      count: args[2].toInt32(),
      api: "libc.write"
    });
  });

  // -------------------------
  // NETWORK (libc)
  // -------------------------
  // Минимальный и очень устойчивый подход:
  // фиксируем факт сетевых вызовов, а не пытаемся везде парсить sockaddr (это можно расширять позже)

  ["connect", "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg"].forEach(function (fn) {
    hookExport(fn, function (args) {
      send({
        kind: "net_call",
        api: "libc." + fn,
        fd: args[0].toInt32()
      });
    });
  });

  // Финальный статус
  send({ kind: "frida_status", status: "hooks_attached" });
})();
"""


# ================== severity helpers ==================

def _severity_for_file_event(location: str, op: str) -> Severity:
    # external + write/open* -> более опасно
    if location == "external":
        if "write" in op:
            return Severity.HIGH
        return Severity.MEDIUM

    if location == "internal":
        if "write" in op:
            return Severity.MEDIUM
        return Severity.INFO

    # other/unknown
    if "write" in op:
        return Severity.MEDIUM
    return Severity.INFO


def _severity_for_net_call(api: str) -> Severity:
    # очень простая эвристика: connect/send* => LOW, recv* => INFO
    if api and ("connect" in api or "send" in api):
        return Severity.LOW
    return Severity.INFO


# ================== Dynamic analysis runner ==================

def run_dynamic_analysis_session(
    package_name: str,
    duration: int = 60,
    device_id: Optional[str] = None,
) -> List[Threat]:
    """
    Native-only динамический анализ:
    - файловые системные вызовы (open*/read/write)
    - сетевые системные вызовы (connect/send*/recv*)
    Работает даже для NDK/Qt приложений.
    """
    threats: List[Threat] = []

    # 1) Получаем устройство
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device(timeout=10)

    # 2) Убеждаемся, что приложение запущено
    proc = _run_adb(["shell", "pidof", package_name], device_id=device_id)
    pids: list[int] = []
    if proc.returncode == 0 and proc.stdout.strip():
        for part in proc.stdout.strip().split():
            try:
                pids.append(int(part))
            except ValueError:
                pass

    if not pids:
        launch_app_via_adb(package_name, device_id=device_id)
        time.sleep(2)
        proc2 = _run_adb(["shell", "pidof", package_name], device_id=device_id)
        if proc2.returncode == 0 and proc2.stdout.strip():
            for part in proc2.stdout.strip().split():
                try:
                    pids.append(int(part))
                except ValueError:
                    pass

    if not pids:
        raise RuntimeError(f"[dyn] Не удалось получить PID процесса {package_name}. Приложение не запущено?")

    # 3) Выбираем PID: пробуем по очереди (если несколько процессов)
    chosen_session = None
    chosen_pid = None
    chosen_script = None

    def _try_attach(pid: int):
        session = device.attach(pid)
        script = session.create_script(FRIDA_SCRIPT)

        got = {"hooks": False}

        def _probe_message(message, data):
            # не глотаем ошибки JS
            if message.get("type") == "error":
                print("[dyn] FRIDA SCRIPT ERROR (probe):", message.get("stack") or message)
                return
            if message.get("type") != "send":
                return
            payload = message.get("payload") or {}
            if payload.get("kind") == "frida_status" and payload.get("status") == "hooks_attached":
                got["hooks"] = True

        script.on("message", _probe_message)
        script.load()
        time.sleep(1.0)
        return session, script, got["hooks"]

    for candidate in pids:
        print(f"[dyn] Trying attach pid={candidate} ...")
        try:
            session, script, ok = _try_attach(candidate)
            if ok:
                chosen_session, chosen_script, chosen_pid = session, script, candidate
                break
            # если hooks_attached не получили — отсоединяемся
            try:
                session.detach()
            except Exception:
                pass
        except Exception as e:
            print(f"[dyn] attach failed pid={candidate}: {e}")
            continue

    if chosen_session is None or chosen_script is None or chosen_pid is None:
        # fallback: attach к первому pid без "probe"
        chosen_pid = pids[0]
        print(f"[dyn] Fallback attach to pid={chosen_pid}")
        chosen_session = device.attach(chosen_pid)
        chosen_script = chosen_session.create_script(FRIDA_SCRIPT)

    print(f"[dyn] Using pid={chosen_pid} for instrumentation")

    # 4) Основной on_message: собираем Threat + печатаем статусы hook_ok/hook_missing
    def on_message(message, data):
        # Очень важно: показываем ошибки frida-скрипта
        if message.get("type") == "error":
            print("[dyn] FRIDA SCRIPT ERROR:", message.get("stack") or message)
            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="frida_script_error",
                    title="Ошибка Frida-скрипта",
                    description=str(message.get("stack") or message),
                    severity=Severity.HIGH,
                )
            )
            return

        if message.get("type") != "send":
            return

        payload = message.get("payload") or {}
        kind = payload.get("kind")

        if kind == "frida_status":
            hook = payload.get("hook")
            if hook:
                print(f"[dyn] Frida status: {payload.get('status')} ({hook})")
            else:
                print(f"[dyn] Frida status: {payload.get('status')}")
            return

        if kind == "file_io":
            op = payload.get("op", "")
            path = payload.get("path", "")
            location = payload.get("location", "unknown")
            api = payload.get("api", "")
            sev = _severity_for_file_event(location, op)

            desc = f"Native file I/O: {op} path={path} ({location}), via {api}"
            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="dynamic_file_io_native",
                    title="Файловая операция (native)",
                    description=desc,
                    severity=sev,
                    location=path,
                    metadata=payload,
                )
            )
            return

        if kind == "net_call":
            api = payload.get("api", "")
            fd = payload.get("fd")
            sev = _severity_for_net_call(api)

            threats.append(
                Threat(
                    analyzer=DYNAMIC_ANALYZER_NAME,
                    type="net_call_native",
                    title="Сетевой вызов (native)",
                    description=f"Вызван {api} (fd={fd})",
                    severity=sev,
                    metadata=payload,
                )
            )
            return

    chosen_script.on("message", on_message)
    # НЕ делаем chosen_script.load() повторно — он уже загружен в _try_attach()

    print(f"[dyn] Hooks loaded, listening for {duration} seconds...")
    time.sleep(max(1, duration))

    try:
        chosen_session.detach()
    except Exception:
        pass

    if not threats:
        # чтобы PDF не выглядел пустым как "ничего не запустилось"
        threats.append(
            Threat(
                analyzer=DYNAMIC_ANALYZER_NAME,
                type="dynamic_session_summary",
                title="Динамический анализ выполнен",
                description=(
                    "Сессия динамического анализа выполнена, но за отведённое время "
                    "не было зафиксировано событий, попадающих под текущие хуки (native file/network). "
                    "Увеличьте duration и/или активнее взаимодействуйте с приложением."
                ),
                severity=Severity.INFO,
            )
        )

    print(f"[dyn] Dynamic session finished, collected {len(threats)} events.")
    return threats
