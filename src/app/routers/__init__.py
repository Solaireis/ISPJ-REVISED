# api routers
from .api.all_roles import allroles_api
from .api.guests import guest_api
from .api.users import user_api
from .api.general import general_api
from .api.lenient import lenient_api
from .api.root import root_api
from .api.admin import admin_api

# web routers
from .web.all_roles import allroles_router
from .web.general import general_router
from .web.admin import admin_router
from .web.guests import guest_router
from .web.users import user_router
from .web.root import maintenance_router