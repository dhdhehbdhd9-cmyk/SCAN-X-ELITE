"""Stable protocol for engines implemented in subsequent phases."""
from __future__ import annotations
from typing import Protocol, Iterable
from scanx_app.core.models import ScanRequest, Finding

class Engine(Protocol):
    name: str
    def scan(self, request: ScanRequest) -> Iterable[Finding]: ...
