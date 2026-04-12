"""Root ASGI entrypoint for validators expecting app:app."""

from server.app import app, main

__all__ = ["app", "main"]
