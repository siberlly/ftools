from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .models import CorrelationHit


def normalize_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    text = path.strip().strip('"')
    text = text.replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.lstrip("/").lower()


def evidence_relative(target_path: str | None) -> str | None:
    normalized = normalize_windows_path(target_path)
    if not normalized:
        return None
    marker = ":/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
    elif normalized.startswith(":"):
        normalized = normalized[1:].lstrip("/")
    return normalized or None


IE_SUFFIX_RE = re.compile(r"\[(\d{1,3})\]$")


def strip_ie_suffix(name: str | None) -> str | None:
    """IE/WebCache appends [1], [2] to duplicate download names."""
    if not name:
        return None
    stem, dot, extension = name.partition(".")
    match = IE_SUFFIX_RE.search(stem)
    if not match:
        return None
    cleaned = IE_SUFFIX_RE.sub("", stem)
    return f"{cleaned}{dot}{extension}" if dot else cleaned


def basename_variants(name: str | None) -> list[str]:
    if not name:
        return []
    variants = [name]
    stripped = strip_ie_suffix(name)
    if stripped and stripped != name:
        variants.append(stripped)
    return variants


def basename_of(path: str | None) -> str | None:
    normalized = normalize_windows_path(path)
    if not normalized:
        return None
    return os.path.basename(normalized) or None


@dataclass(slots=True)
class CorrelationResult:
    hits: list[CorrelationHit]
    confidence: str
    reasons: list[str]
    warnings: list[str]
    normalized_target: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [hit.to_dict() for hit in self.hits],
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "normalized_target": self.normalized_target,
        }


def correlate(
    *,
    target_path: str | None,
    filename: str | None,
    download_size: int | None,
    lookup_exact,
    lookup_basename,
    limit: int = 50,
) -> CorrelationResult:
    """Match a download target against filesystem index entries.

    `lookup_exact(relpath)` and `lookup_basename(basename, limit)` are callables
    provided by the service so this module stays storage agnostic.
    """
    reasons: list[str] = []
    warnings: list[str] = []
    hits: list[CorrelationHit] = []
    relative = evidence_relative(target_path)
    basename = basename_of(target_path) or (
        filename.lower() if filename else None
    )
    if not relative and not basename:
        return CorrelationResult([], "none", ["no target path"], [], None)

    if relative:
        exact = lookup_exact(relative)
        reasons.append(f"exact path match on {relative}")
        for entry in exact:
            hits.append(
                _hit(entry, 0.99, "exact evidence path", download_size)
            )

    if not hits and basename:
        seen: set[int] = set()
        candidates = []
        for variant in basename_variants(basename):
            for entry in lookup_basename(variant, limit):
                if entry.id in seen:
                    continue
                seen.add(entry.id)
                candidates.append(entry)
                if variant != basename:
                    reasons.append(f"IE duplicate suffix stripped: {variant}")
        if len(candidates) == 1:
            hits.append(
                _hit(candidates[0], 0.7, "unique basename match", download_size)
            )
            reasons.append("single basename candidate")
        elif len(candidates) > 1:
            reasons.append(f"{len(candidates)} basename candidates")
            sized = [
                entry for entry in candidates
                if download_size is not None
                and getattr(entry, "size", None) is not None
                and int(entry.size) == int(download_size)
            ]
            if len(sized) == 1:
                hits.append(
                    _hit(
                        sized[0],
                        0.75,
                        "basename+size match (other candidates differ in size)",
                        download_size,
                    )
                )
                warnings.append(
                    "basename is shared but only one candidate matches the "
                    "recorded size; treat as an indicator only"
                )
                for entry in candidates:
                    if entry.id != sized[0].id:
                        hits.append(
                            _hit(
                                entry,
                                0.3,
                                "basename match with size mismatch",
                                download_size,
                            )
                        )
                candidates = []
            if candidates:
                warnings.append(
                    "multiple files share the downloaded basename; "
                    "treat as an indicator only"
                )
                for entry in candidates[:limit]:
                    hits.append(
                        _hit(
                            entry,
                            0.4,
                            "basename match (ambiguous)",
                            download_size,
                        )
                    )
        else:
            reasons.append("no basename candidate")
            warnings.append("no filesystem entry matches the download target")

    if not hits and relative:
        warnings.append("no filesystem entry matches the download target")

    hits.sort(key=lambda item: (-item.confidence, item.path))
    if not hits:
        confidence = "none"
    elif hits[0].confidence >= 0.95:
        confidence = "high"
    elif hits[0].confidence >= 0.65:
        confidence = "medium"
    else:
        confidence = "low"
    return CorrelationResult(hits, confidence, reasons, warnings, relative)


def _hit(entry, confidence: float, reason: str, download_size: int | None) -> CorrelationHit:
    size_matches = None
    if download_size is not None and getattr(entry, "size", None) is not None:
        size_matches = int(entry.size) == int(download_size)
        if not size_matches:
            reason = f"{reason}; size differs"
    return CorrelationHit(
        entry_id=int(entry.id),
        path=entry.full_path,
        basename=entry.basename,
        inode=getattr(entry, "inode", None),
        size=getattr(entry, "size", None),
        allocated=bool(getattr(entry, "allocated", False)),
        deleted=bool(getattr(entry, "deleted", False)),
        modified_time=getattr(entry, "modified_time", None),
        confidence=confidence,
        reason=reason,
        size_matches=size_matches,
    )
