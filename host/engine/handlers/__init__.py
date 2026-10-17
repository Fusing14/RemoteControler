"""Manejadores nativos de ejecución en Windows sin subshell."""

from host.engine.handlers.media import execute_media_command
from host.engine.handlers.power import execute_power_command
from host.engine.handlers.apps import execute_app_command

__all__ = [
    "execute_media_command",
    "execute_power_command",
    "execute_app_command",
]
