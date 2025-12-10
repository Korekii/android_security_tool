# core/apk_loader.py
from functools import lru_cache
from typing import Tuple

from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK


@lru_cache(maxsize=16)
def load_apk(apk_path: str) -> APK:
    """
    Быстрая, кэшированная загрузка APK — манифест, права, ресурсы.
    """
    return APK(apk_path)


@lru_cache(maxsize=16)
def load_apk_with_analysis(apk_path: str) -> Tuple[APK, list, object]:
    """
    Полная загрузка: APK + список DEX + объект анализа dx (для DEX-анализа).
    """
    a, d, dx = AnalyzeAPK(apk_path)
    return a, d, dx
