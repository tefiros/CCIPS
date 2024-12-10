import uuid
from connexion import problem

from i2nsf import I2NSF

NOTFOUND_404 = problem(status=404, title="uuid does not exist in the controller",
                       detail=f'{uuid} does not exist in the controller')



def remove_path_internal_error(e: Exception):
    """
    Returns the InternalServerError exception if the i2nsf was not removed because there was an error in the
    OPoTController

    :param e: Exception that has been produced
    :return:
    :rtype: ConnexionResponse
    """
    return problem(status=500, title="There was an error in the server when removing deleting the I2NSF",
                   detail=str(e))

def create_path_internal_error(e: Exception):
    """
    Returns the InternalServerError exception if the i2nsf was not removed because there was an error in the
    OPoTController

    :param e: Exception that has been produced
    :return:
    :rtype: ConnexionResponse
    """
    return problem(status=500, title="There was an error in the server when creating the I2NSF",
                   detail=str(e))

def create_default_response(message: str):
    return {
        "msg": message,
        "status": 200
    }


def create_status_response(i2nsf_id, i2nsf: I2NSF):
    nodes = []
    for k, v in i2nsf.ipsec_associations.items():
        nodes.append({
            "ipControl": v.ip_local_control,
            "ipData": v.ip_local_data,
            "networkInternal": v.ip_local_internal
        })
    return {
        "uuid" : i2nsf_id,
        "status": "running",
        "i2nsfInfo": {
            "nodes": nodes,
            "encAlg": i2nsf.enc_alg,
            "intAlg": i2nsf.int_alg,
            "softLifetime": i2nsf.soft_lifetime,
            "hardLifetime": i2nsf.hard_lifetime,
        },
    }


class SingletonMeta(type):
    """
    The Singleton class can be implemented in different ways in Python. Some
    possible methods include: base class, decorator, metaclass. We will use the
    metaclass because it is best suited for this purpose.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Possible changes to the value of the `__init__` argument do not affect
        the returned instance.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class Controller(metaclass=SingletonMeta):

    def __init__(self):
        self.running_i2nsf = {}

    def create_i2nsf(self, data):
        i2nsf_instance = I2NSF(data)
        i2nsf_id = str(uuid.uuid4())
        for node in data['nodes']:
            try:
                i2nsf_instance.sign_up(node['ipControl'], node['networkInternal'], node['ipData'], node.get('ipDMZ',None))
            except Exception as e:
                return create_path_internal_error(e)
        self.running_i2nsf[i2nsf_id] = i2nsf_instance
        return create_status_response(i2nsf_id, i2nsf_instance)

    def delete_i2nsf(self, i2nsf_id):
        if self.running_i2nsf.get(i2nsf_id, None) is None:
            return NOTFOUND_404
        try:
            self.running_i2nsf[i2nsf_id].remove_ipsec_policies()
        except Exception as e:
            traceback.print_exc()
            return remove_path_internal_error(e)
        # self.running_i2nsf.pop(i2nsf_id)
        return create_default_response('The path has been removed')

    def status_i2nsf(self, i2nsf_id):
        if self.running_i2nsf.get(i2nsf_id, None) is None:
            return NOTFOUND_404
        return create_status_response(i2nsf_id,self.running_i2nsf[i2nsf_id])
