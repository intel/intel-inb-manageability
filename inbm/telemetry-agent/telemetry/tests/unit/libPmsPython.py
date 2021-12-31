from enum import Enum, auto


def callback():
    pass


class PmsConnection(object):
    def __init__(self):
        pass

    def Connect(self, type=None):
        pass

    def Disconnect(self):
        pass


class RasSeverity(Enum):
    def __init__(self):
        SeverityAll = auto()


class TelemetryNotificationRequestType(Enum):
    def __init__(self):
        RequestErrorAll = auto()


class PmsTelemetry():
    def __init__(self, conn):
        pass

    def SetRASSeverity(RasSeverity):
        pass

    def RegisterNotificationCallback(callback, TelemetryNotificationRequestType):
        pass


class PmsConnectionType(Enum):
    def __init__(self):
        RM_DAEMON = auto()

    def register_pms_notification(self):
        pass
