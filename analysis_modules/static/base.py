# analyzers/static/base.py
from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import AnalysisResult


class BaseStaticAnalyzer(ABC):
    name: str = "BaseStaticAnalyzer"

    @abstractmethod
    def analyze(self, apk_path: str, analysis: AnalysisResult) -> None:
        """
        Модифицирует объект analysis: добавляет findings, заполняет метаданные.
        """
        raise NotImplementedError
