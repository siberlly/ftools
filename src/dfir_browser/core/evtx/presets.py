from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Preset:
    preset_id: str
    name: str
    description: str
    event_ids: tuple[int, ...]
    channels: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    limitations: str = ""
    rule_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "preset_id": self.preset_id,
            "name": self.name,
            "description": self.description,
            "event_ids": list(self.event_ids),
            "channels": list(self.channels),
            "providers": list(self.providers),
            "limitations": self.limitations,
            "rule_id": self.rule_id or f"preset.{self.preset_id}",
        }


PRESETS: tuple[Preset, ...] = (
    Preset(
        preset_id="authentication",
        name="Authentication",
        description=(
            "Logon, logoff, explicit-credential and special-privilege events "
            "from the Security channel."
        ),
        event_ids=(4624, 4625, 4634, 4647, 4648, 4672),
        channels=("Security",),
        limitations=(
            "Only present if logon auditing is enabled and the Security log "
            "retains these records. Absence of an event is not absence of logon."
        ),
    ),
    Preset(
        preset_id="process_execution",
        name="Process execution",
        description=(
            "Process creation via Security 4688 and Sysmon Event ID 1."
        ),
        event_ids=(4688, 1),
        channels=("Security", "Microsoft-Windows-Sysmon/Operational"),
        providers=("Microsoft-Windows-Sysmon",),
        limitations=(
            "4688 requires process-creation auditing. Sysmon rows only exist if "
            "Sysmon is installed and its log was collected."
        ),
    ),
    Preset(
        preset_id="service_persistence",
        name="Service persistence",
        description="Service installation via System 7045 and Security 4697.",
        event_ids=(7045, 4697),
        channels=("System", "Security"),
        limitations=(
            "Service installation is not by itself malicious; correlate with "
            "binary path and signer."
        ),
    ),
    Preset(
        preset_id="scheduled_tasks",
        name="Scheduled tasks",
        description=(
            "Task create/update/delete/run/disable/enable events from Security "
            "and the TaskScheduler operational channel."
        ),
        event_ids=(4698, 4699, 4700, 4701, 4702, 106, 140, 141, 200, 201),
        channels=(
            "Security",
            "Microsoft-Windows-TaskScheduler/Operational",
        ),
        limitations=(
            "TaskScheduler event IDs vary by Windows build; only records present "
            "in this image are returned."
        ),
    ),
    Preset(
        preset_id="powershell",
        name="PowerShell",
        description=(
            "PowerShell engine and script-block logging events (4103, 4104) and "
            "classic PowerShell channel activity."
        ),
        event_ids=(4103, 4104, 400, 600),
        channels=(
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
        ),
        limitations=(
            "Script-block logging must be enabled. Script text is evidence data; "
            "it is never executed."
        ),
    ),
    Preset(
        preset_id="defender",
        name="Defender",
        description="Defender detection, action and failure events.",
        event_ids=(1116, 1117, 1118, 1119, 1006, 1007, 1015),
        channels=("Microsoft-Windows-Windows Defender/Operational",),
        limitations=(
            "Defender events show what Defender recorded, not what the attacker "
            "did. Only present if the Defender log was collected."
        ),
    ),
    Preset(
        preset_id="log_clearing",
        name="Log clearing / tampering",
        description=(
            "Security log cleared (1102) and System audit log cleared (104)."
        ),
        event_ids=(1102, 104),
        channels=("Security", "System"),
        limitations=(
            "A cleared log may also be a legitimate administrative action; "
            "absence of 1102 does not prove logs were untouched."
        ),
    ),
    Preset(
        preset_id="sysmon_network_file_registry",
        name="Sysmon network / file / registry",
        description=(
            "Sysmon network connection (3), image load (7), file create (11) "
            "and registry value set (13)."
        ),
        event_ids=(3, 7, 11, 13),
        channels=("Microsoft-Windows-Sysmon/Operational",),
        providers=("Microsoft-Windows-Sysmon",),
        limitations=(
            "Requires Sysmon and the relevant configuration; nothing is returned "
            "when the channel is absent."
        ),
    ),
)

PRESET_MAP = {preset.preset_id: preset for preset in PRESETS}


class PresetNotFound(ValueError):
    pass


def get_preset(preset_id: str) -> Preset:
    try:
        return PRESET_MAP[preset_id]
    except KeyError as exc:
        raise PresetNotFound(f"unknown preset: {preset_id}") from exc


def list_presets() -> list[dict[str, Any]]:
    return [preset.to_dict() for preset in PRESETS]
