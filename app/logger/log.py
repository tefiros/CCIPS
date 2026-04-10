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

import logging 
import sys 
from typing import Any

class LogLevel:
    DebugLevel = 0
    InfoLevel = 1
    WarningLevel = 2
    ErrorLevel = 3

log = None

class Logger:
    def __init__(self):
        self.logger = logging.getLogger("default log")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if self.logger.handlers:
            self.logger.handlers.clear()

        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(prefix)s%(asctime)s %(filename)s:%(lineno)d %(message)s",
            datefmt="%Y/%m/%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        self.handler = handler
        self.logger.addHandler(handler)

        #Debub prefix
        pref = self._make_prefixed("DEBUG: ")
        self.debug = pref.debug
        self.info = pref.info
        self.warning = pref.warning
        self.error = pref.error

    def _make_prefixed(self, prefix: str):
        class PrefixedAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                kwargs["extra"] = {"prefix": prefix}
                return msg, kwargs

        return PrefixedAdapter(self.logger, {})


def new_logger():
    global log
    log = Logger()
    return log

def _ensurelogogger():
    global log
    if log is None:
        new_logger()      # antes usabas NewLogger()
    return log

def debug(format: str, *v: Any):
    l = _ensurelogogger()
    msg = format % v if v else format
    l.debug(msg, stacklevel=2)      # <- aquí

def info(format: str, *v: Any):
    l = _ensurelogogger()
    msg = format % v if v else format
    l.info(msg, stacklevel=2)       # <- y aquí

def warning(format: str, *v: Any):
    l = _ensurelogogger()
    msg = format % v if v else format
    l.warning(msg, stacklevel=2)

def error(format: str, *v: Any):
    l = _ensurelogogger()
    msg = format % v if v else format
    l.error(msg, stacklevel=2)

def fatal(format: str, *v: Any):
    l = _ensurelogogger()
    msg = format % v if v else format
    l.error(msg, stacklevel=2)
    sys.exit(1)