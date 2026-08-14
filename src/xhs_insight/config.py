"""Application configuration with conservative local-only defaults."""

from __future__ import annotations

import math
import os
import platform
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, *, legacy: str | None = None, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None and legacy:
        value = os.getenv(legacy)
    return default if value is None else value


def _bool_env(name: str, default: bool = False, *, legacy: str | None = None) -> bool:
    value = _env(name, legacy=legacy)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(
    name: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: int | None = None,
    legacy: str | None = None,
) -> int:
    value = int(_env(name, legacy=legacy, default=str(default)) or str(default))
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def default_state_dir() -> Path:
    override = _env("CRIMSONFLUX_STATE_DIR", legacy="XHS_INSIGHT_STATE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
        legacy = base / "XHS Insight"
        return legacy if legacy.exists() else base / "CrimsonFlux"
    if platform.system() == "Windows":
        base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        legacy = base / "XHS Insight"
        return legacy if legacy.exists() else base / "CrimsonFlux"
    base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    legacy = base / "xhs-insight"
    return legacy if legacy.exists() else base / "crimsonflux"


@dataclass(frozen=True, slots=True)
class Settings:
    host: str
    port: int
    state_dir: Path
    export_dir: Path
    max_keyword_items: int
    max_user_items: int
    pause_min_seconds: float
    pause_max_seconds: float
    open_browser: bool
    max_job_retries: int = 12

    def __post_init__(self) -> None:
        """Enforce the bind boundary for every construction path.

        ``dataclasses.replace`` is used by the CLI to apply ``serve`` overrides,
        so validating only environment parsing would let ``--host`` bypass the
        local-only policy.
        """
        if self.host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
            raise ValueError("CRIMSONFLUX_HOST must be a local bind address")
        if self.host == "0.0.0.0" and not _bool_env(
            "CRIMSONFLUX_ALLOW_CONTAINER_BIND",
            legacy="XHS_INSIGHT_ALLOW_CONTAINER_BIND",
        ):
            raise ValueError(
                "0.0.0.0 is allowed only inside the hardened container; "
                "native mode must bind to 127.0.0.1"
            )

    @classmethod
    def from_env(cls) -> Settings:
        host = str(
            _env("CRIMSONFLUX_HOST", legacy="XHS_INSIGHT_HOST", default="127.0.0.1")
        ).strip()
        pause_min = float(
            _env(
                "CRIMSONFLUX_REQUEST_PAUSE_MIN",
                legacy="XHS_REQUEST_PAUSE_MIN",
                default="2",
            )
            or "2"
        )
        pause_max = float(
            _env(
                "CRIMSONFLUX_REQUEST_PAUSE_MAX",
                legacy="XHS_REQUEST_PAUSE_MAX",
                default="4",
            )
            or "4"
        )
        if (
            not math.isfinite(pause_min)
            or not math.isfinite(pause_max)
            or pause_min < 2
            or pause_max < pause_min
        ):
            raise ValueError("request pause range must be at least 2 seconds")
        export_override = _env(
            "CRIMSONFLUX_EXPORT_DIR",
            legacy="XHS_INSIGHT_EXPORT_DIR",
            default="./exports",
        )
        return cls(
            host=host,
            port=_int_env(
                "CRIMSONFLUX_PORT", 8765, minimum=1, legacy="XHS_INSIGHT_PORT"
            ),
            state_dir=default_state_dir(),
            export_dir=Path(str(export_override)).expanduser().resolve(),
            max_keyword_items=_int_env(
                "CRIMSONFLUX_MAX_KEYWORD_ITEMS",
                1000,
                minimum=1,
                legacy="XHS_MAX_KEYWORD_ITEMS",
            ),
            max_user_items=_int_env(
                "CRIMSONFLUX_MAX_USER_ITEMS",
                10000,
                minimum=1,
                legacy="XHS_MAX_USER_ITEMS",
            ),
            pause_min_seconds=pause_min,
            pause_max_seconds=pause_max,
            open_browser=not _bool_env(
                "CRIMSONFLUX_NO_BROWSER", legacy="XHS_INSIGHT_NO_BROWSER"
            ),
            max_job_retries=_int_env(
                "CRIMSONFLUX_MAX_JOB_RETRIES",
                12,
                minimum=0,
                maximum=20,
            ),
        )

    def prepare(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)
