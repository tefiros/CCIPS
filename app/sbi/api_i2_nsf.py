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
import uuid
from logger.log import Logger, new_logger, error, fatal, info
from controller_i2nsf.handler import Handler
from controller_i2nsf.notifications import SADBExpireNotification

def api_process_rekey(handler_id, ipsec_name):
    from nbi_swagger.routers import get_storage
    log = Logger() 
    storage = get_storage()
    try:
        handler_id = uuid.UUID(handler_id)
    except ValueError:
        return jsonify({"error": "Invalid handler_id"}), 400
    notification = SADBExpireNotification()
    notification.EventType = "sadb-expire"
    notification.IPsecName = ipsec_name
    notification.SoftLifeTime = True
   
    handler = storage.get_handler(handler_id)
    if handler is None:
        log.info(f"Rekey for unknown handler {handler_id} ignored (already deleted)")
        return jsonify({"status": "Handler not found; rekey ignored"}), 200
    err = handler.process_rekey(notification, handler_id)

    if err:
        return jsonify({"error": f"api_process_rekey: {str(err)}"}), 400

    return jsonify({"status": "Rekey processed successfully"}), 200
