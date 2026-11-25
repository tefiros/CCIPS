# api_i2_nsf.py
"""
© 2026 Telefónica Innovación Digital 
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
limitations under the License.
"""
from flask import request, jsonify
from .models import I2NSFRequest
import uuid as uuid_lib

def api_create_i2nsf():
    from .routers import get_storage
    
    try:
        cfg_request = request.get_json()
        if cfg_request is None:
            return jsonify({"error": "Invalid JSON"}), 400
        cfg = I2NSFRequest(**cfg_request)
        if not cfg.method:
            cfg.method = "netconf-ssh"  # Valor por defecto
        storage = get_storage()
        print("POST storage object id:", hex(id(storage)))
        response, err = storage.create_handler(cfg)
        if err:
            return jsonify({"error": str(err)}), 400
        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": f"api_create_i2nsf: {str(e)}"}), 400


def api_delete_i2nsf(handler_id):
    from .routers import get_storage
    
    raw_id = handler_id
    parsed_id = uuid_lib.UUID(raw_id.strip())
    storage = get_storage()
    err = storage.delete_handler(parsed_id)
    if err:
        return jsonify({"error": f"api_delete_i2nsf: {str(err)}"}), 400
    
    return jsonify({"status": f"Handler {parsed_id} deleted"}), 200

def api_status_i2nsf(handler_id):
    from .routers import get_storage

    raw_id = handler_id
    parsed_id = uuid_lib.UUID(raw_id.strip())
    storage = get_storage()

    response, err  = storage.get_config(parsed_id)
    if err:
        return jsonify({"error": f"api_status_i2nsf: {str(err)}"}), 400
    return jsonify(response), 200


def api_all_ids_i2nsf():
    from .routers import get_storage

    storage = get_storage()
    response, err  = storage.get_all_ids()
    if err:
        return jsonify({"error": f"api_all_ids_i2nsf: {str(err)}"}), 400
    return jsonify(response), 200