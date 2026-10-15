from .farmers import router as farmers_router
from .partners import router as partners_router
from .admin import router as admin_router
from .dashboard import router as dashboard_router
from .dev import router as dev_router

__all__ = ["farmers_router", "partners_router", "admin_router", "dashboard_router", "dev_router"]

