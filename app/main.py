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

import ssl, os, subprocess, threading

from flask import Flask
from controller_i2nsf.handler import StorageHandler
from controller_i2nsf.templates import load_templates
from nbi_swagger.routers import new_router
from sbi.api_i2_nsf import api_process_rekey
from logger.log import Logger, new_logger, error, fatal, info

def main():
    new_logger()
    info("HTTPS server started")
    
    try:
        load_templates("../app/templates")
    except Exception as e:
        error(f"Failed to load templates: {e}")
        raise
    
    app = Flask(__name__)
    storage = StorageHandler()
    router = new_router(storage)
    app.register_blueprint(router)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ciphers("DEFAULT:@SECLEVEL=2")

    print("OPENSSL_CONF:", os.environ.get("OPENSSL_CONF"))
    print("OPENSSL_MODULES:", os.environ.get("OPENSSL_MODULES"))
    context.load_cert_chain('./certs_PQC/srv.crt', './certs_PQC/srv.key')

    sbi_app = Flask(__name__)
    sbi_app.add_url_rule(
        rule="/process_rekey/<handler_id>/<path:ipsec_name>",
        endpoint="ApiProcessRekey",
        view_func=api_process_rekey,
        methods=["POST"]
    )

    def run_sbi_app():
        info("Starting SBI HTTPS server on port 5001")
        sbi_app.run(host="0.0.0.0", port=5001, debug=False, ssl_context=context, threaded=True)

    sbi_thread = threading.Thread(target=run_sbi_app, daemon=True)
    sbi_thread.start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        ssl_context=context
    )

if __name__ == "__main__":
    main()
