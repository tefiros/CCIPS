import logging.config

LOG_PATH = "/tmp/"


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


class Logger(metaclass=SingletonMeta):
    def __init__(self):
        logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
        self.rootLogger = logging.getLogger("root_logger")
        self.rootLogger.setLevel(logging.INFO)

        fileHandler = logging.FileHandler("{0}/{1}.log".format(LOG_PATH, "i2nsf"))
        fileHandler.setFormatter(logFormatter)
        self.rootLogger.addHandler(fileHandler)

        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(logFormatter)
        self.rootLogger.addHandler(consoleHandler)
        self.rootLogger.info("Logger setup")

    def get_logger(self):
        return self.rootLogger
