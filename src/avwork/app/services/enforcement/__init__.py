from app.services.enforcement.backends import get_backend_adapter
from app.services.enforcement.backends import base as _base  # noqa: F401
from app.services.enforcement.backends import linux as _linux  # noqa: F401
from app.services.enforcement.backends import macos as _macos  # noqa: F401
from app.services.enforcement.backends import windows as _windows  # noqa: F401

__all__ = ['get_backend_adapter']
