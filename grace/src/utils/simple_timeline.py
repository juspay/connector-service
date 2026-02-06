"""
Simple timeline tracker for GRACE-UCS workflow phases.

This module provides a lightweight timeline tracking system that logs timestamps
as each phase completes, then calculates and saves durations when the workflow finishes.
"""

import json
from datetime import datetime, time
from pathlib import Path
from typing import Dict, Any, Optional


class SimpleTimeline:
    """Super simple timeline tracker for GRACE workflow phases."""

    def __init__(self, connector_name: str):
        """
        Initialize timeline for a connector.

        Args:
            connector_name: Name of the connector (e.g., "stripe", "adyen")
        """
        self.connector_name = connector_name

        # Find grace root directory by looking for rulesbook/codegen marker
        # This works regardless of CWD or where this file is located within grace/
        module_path = Path(__file__).resolve()
        grace_root = None

        for parent in module_path.parents:
            if (parent / "rulesbook" / "codegen").exists():
                grace_root = parent
                break

        if not grace_root:
            raise RuntimeError(
                f"Cannot locate grace root directory with rulesbook/codegen structure. "
                f"Searched from {module_path}"
            )

        self.timeline_file = grace_root / "rulesbook" / "codegen" / "timeline" / f"{connector_name}_timeline.json"
        self.timeline_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing timeline if it exists, otherwise create new
        if self.timeline_file.exists():
            with open(self.timeline_file, 'r') as f:
                self.data = json.load(f)
        else:
            # Initialize empty timeline
            self.data: Dict[str, Any] = {
                "connector_name": connector_name,
                "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "phases": {},
                "completed_at": None,
                "total_duration": None,
                "workflow_status": "in_progress"
            }
            self._save()

    def log_phase_start(self, phase_name: str):
        """
        Log when a phase starts.

        Args:
            phase_name: Name of the phase (e.g., "phase_1_tech_spec_validation")
        """
        self.data["phases"][phase_name] = {
            "start": datetime.now().strftime("%H:%M:%S"),
            "end": None,
            "duration": None,
            "status": "in_progress"
        }
        self._save()

    def log_phase_end(self, phase_name: str, status: str = "success"):
        """
        Log when a phase ends.

        Args:
            phase_name: Name of the phase
            status: Status of the phase ("success" or "failed")
        """
        if phase_name in self.data["phases"]:
            self.data["phases"][phase_name]["end"] = datetime.now().strftime("%H:%M:%S")
            self.data["phases"][phase_name]["status"] = status
            self._save()

    def finalize(self):
        """
        Calculate all durations and mark workflow complete.

        This should be called at the very end of the workflow (success or failure).
        It calculates durations for all phases and the total workflow duration.
        """
        # Calculate duration for each phase
        for phase_name, phase_data in self.data["phases"].items():
            if phase_data["start"] and phase_data["end"]:
                duration_seconds = self._calculate_duration(phase_data["start"], phase_data["end"])
                phase_data["duration"] = self._format_duration(duration_seconds)

        # Calculate total duration
        if self.data["phases"]:
            first_phase = list(self.data["phases"].values())[0]
            last_phase = list(self.data["phases"].values())[-1]
            if first_phase["start"] and last_phase["end"]:
                total_seconds = self._calculate_duration(first_phase["start"], last_phase["end"])
                self.data["total_duration"] = self._format_duration(total_seconds)

        # Mark as completed
        self.data["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check if any phase failed
        failed = any(p["status"] == "failed" for p in self.data["phases"].values())
        self.data["workflow_status"] = "failed" if failed else "completed"

        self._save()

    def _calculate_duration(self, start_time: str, end_time: str) -> int:
        """
        Calculate duration in seconds between HH:MM:SS times.

        Args:
            start_time: Start time in HH:MM:SS format
            end_time: End time in HH:MM:SS format

        Returns:
            Duration in seconds
        """
        # Parse time strings to time objects
        start_parts = start_time.split(":")
        end_parts = end_time.split(":")

        start_h, start_m, start_s = int(start_parts[0]), int(start_parts[1]), int(start_parts[2])
        end_h, end_m, end_s = int(end_parts[0]), int(end_parts[1]), int(end_parts[2])

        # Convert to total seconds
        start_total_seconds = start_h * 3600 + start_m * 60 + start_s
        end_total_seconds = end_h * 3600 + end_m * 60 + end_s

        # Calculate difference (handle day boundary if end < start)
        if end_total_seconds >= start_total_seconds:
            return end_total_seconds - start_total_seconds
        else:
            # Crossed midnight
            return (24 * 3600) - start_total_seconds + end_total_seconds

    def _format_duration(self, seconds: int) -> str:
        """
        Format seconds as human-readable duration.

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted duration (e.g., "5m 30s", "1h 15m 30s", "43s")
        """
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60

        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"

    def _save(self):
        """Save timeline data to JSON file."""
        with open(self.timeline_file, 'w') as f:
            json.dump(self.data, f, indent=2)
