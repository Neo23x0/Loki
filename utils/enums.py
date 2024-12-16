from enum import Enum

class MesType(Enum):
    NOTICE = 0
    INFO = 1
    WARNING = 2
    ALERT = 3
    DEBUG = 4
    ERROR = 5
    RESULT = 6
    CRITICAL = 7

    def __str__(self):
        return {
            MesType.INFO: "INFO",
            MesType.WARNING: "WARNING",
            MesType.ALERT: "ALERT",
            MesType.DEBUG: "DEBUG",
            MesType.ERROR: "ERROR",
            MesType.RESULT: "RESULT",
            MesType.CRITICAL: "CRITICAL"
        }[self]