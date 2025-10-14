import os

from flask import Flask # Import Flask class form framework to initialize the app


def create_app():
    app = Flask(__name__) 

    # Import and register blueprints (view, create, delete)
    from .view import view_bp
    from .create import create_bp
    from .delete import delete_bp

    #register blueprints into the app, defines the valid routes of the app
    app.register_blueprint(view_bp)
    app.register_blueprint(create_bp)
    app.register_blueprint(delete_bp)

    return app
