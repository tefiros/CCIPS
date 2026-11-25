''' © 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)
(laura.dominguez.cespedes@telefonica.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. ''' 

from typing import Callable, List, Optional
from functools import wraps
from flask import Blueprint, request
from controller_i2nsf.handler import StorageHandler
from logger.log import new_logger, info
from .api_i2_nsf import (
    api_create_i2nsf,
    api_delete_i2nsf,
    api_status_i2nsf,
    api_all_ids_i2nsf
)

_storage_handler: Optional[StorageHandler] = None

class Route:
    def __init__(self, name: str, method: str, pattern: str, handler_func: Callable):
        self.name = name
        self.method = method
        self.pattern = pattern
        self.handler_func = handler_func

def get_storage() -> StorageHandler:
    global _storage_handler
    if _storage_handler is None:
        raise RuntimeError("Storage handler not initialized. Call new_router() first.")
    return _storage_handler

def _log_route(handler, name):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        info("START %s %s %s", name, request.method, request.path)
        try:
            resp = handler(*args, **kwargs)
        finally:
            info("END   %s %s %s", name, request.method, request.path)
        return resp
    return wrapped

def new_router(storage_handler: StorageHandler) -> Blueprint:
    global _storage_handler
    _storage_handler = storage_handler  # Guardar globalmente
    
    new_logger()
    router = Blueprint('ccips', __name__)
    
    for route in routes:
        handler_with_logger = _log_route(route.handler_func, route.name)
        router.add_url_rule(
            rule=route.pattern,
            endpoint=route.name,
            view_func=handler_with_logger,
            methods=[route.method]
        )
    
    return router

def index() -> str:
    return "Status: CONTROLLER UP"

routes: List[Route] = [
    Route(
        name="Index",
        method="GET",
        pattern="/ccips-all",
        handler_func=api_all_ids_i2nsf
    ),
    
    Route(
        name="ApiCreateI2nsf",
        method="POST",
        pattern="/ccips",
        handler_func=api_create_i2nsf
    ),
    
    Route(
        name="ApiDeleteI2nsf",
        method="DELETE",
        pattern="/ccips/<handler_id>",
        handler_func=api_delete_i2nsf
    ),
    
    Route(
        name="ApiStatusI2nsf",
        method="GET",
        pattern="/ccips/<handler_id>",
        handler_func=api_status_i2nsf
    )
]