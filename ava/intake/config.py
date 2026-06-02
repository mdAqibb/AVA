"""Run configuration: CLI flags layered over an optional config file.

Precedence (highest first): CLI flag > config file > built-in default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# Posture presets map a name to (rate req/s, concurrency).
RATE_PRESETS = {
    "gentle": (2.0, 2),
    "moderate": (5.0, 5),
    "fast": (15.0, 10),
}


@dataclass
class Config:
    target: str = ""
    scope_file: str = "scope.yaml"
    output_dir: str = "output"
    operator: str = ""

    # Posture
    rate: float = 15.0
    concurrency: int = 10
    global_cap: int = 10_000
    max_depth: int = 4
    timeout: float = 15.0
    retries: int = 2

    # Resume an interrupted run instead of starting fresh.
    resume: bool = False
    resume_run_id: str = ""

    # Check toggles. Default posture (per operator decision) is aggressive:
    # passive + safe active + bounded heavy fuzzing on by default.
    passive: bool = True
    active: bool = True
    heavy_fuzzing: bool = True
    dom_crawl: bool = True

    # Hard safety switch, independent of posture. Stays False unless a human
    # explicitly opts a single run into destructive PoC (discouraged).
    allow_destructive: bool = False

    remediation_langs: list[str] = field(default_factory=lambda: ["python", "node"])
    verbose: bool = False

    @classmethod
    def load(cls, args) -> "Config":
        cfg = cls()

        # 1. config file (if present)
        file_path = getattr(args, "config", None)
        if file_path and Path(file_path).is_file():
            data = yaml.safe_load(Path(file_path).read_text(encoding="utf-8")) or {}
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)

        # 2. rate preset
        preset = getattr(args, "rate_preset", None)
        if preset and preset in RATE_PRESETS:
            cfg.rate, cfg.concurrency = RATE_PRESETS[preset]

        # 3. explicit CLI overrides
        for attr in ("target", "scope_file", "output_dir", "operator",
                     "rate", "concurrency", "global_cap", "max_depth",
                     "timeout", "retries", "allow_destructive", "verbose",
                     "resume", "resume_run_id"):
            val = getattr(args, attr, None)
            if val is not None:
                setattr(cfg, attr, val)

        # posture overrides (store_true / store_false flags)
        for attr in ("passive", "active", "heavy_fuzzing", "dom_crawl"):
            val = getattr(args, attr, None)
            if val is not None:
                setattr(cfg, attr, val)

        return cfg
