import os
import connexion
import logging

# Setup the config
import controller
import logging
from controller import I2NSF



def instantiate_api():
    # Setup logging module for API


    # Instantiating the API
    app = connexion.App("__name__", specification_dir=f'{os.path.dirname(__file__)}/api')
    # Adding the OPENAPI template
    app.add_api('./i2nsf-api.yaml')
    # Running the application
    app.run(host="0.0.0.0", port="5000")


def create_i2nsf(body):
    return controller.Controller().create_i2nsf(body)


def status_i2nsf(uuid):
    return controller.Controller().status_i2nsf(uuid)


def delete_i2nsf(uuid):
    return controller.Controller().delete_i2nsf(uuid)


if __name__ == '__main__':
    instantiate_api()
