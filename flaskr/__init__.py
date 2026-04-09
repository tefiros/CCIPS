import os

from flask import Flask, jsonify # Import Flask class form framework to initialize the app
import requests
from .config import CCIPS_API


def _ccips_all_url():
    if CCIPS_API.endswith('/ccips'):
        return CCIPS_API[:-len('/ccips')] + '/ccips-all'
    if CCIPS_API.endswith('/ccips/'):
        return CCIPS_API[:-len('/ccips/')] + '/ccips-all'
    return f"{CCIPS_API.rstrip('/')}-all"


def create_app():
    app = Flask(__name__) 

    # Add route for /ccips-all
    @app.route('/ccips-all')
    def get_ccips_all():
        try:
            response = requests.get(_ccips_all_url())
            if response.status_code == 200:
                data = response.json()
                return jsonify(data)
            else:
                return jsonify({"error": f"API error: {response.status}"}), response.status_code
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Import and register blueprints (view, create, delete)
    from .view import view_bp
    from .create import create_bp
    from .delete import delete_bp

    #register blueprints into the app, defines the valid routes of the app
    app.register_blueprint(view_bp)
    app.register_blueprint(create_bp)
    app.register_blueprint(delete_bp)

    return app
