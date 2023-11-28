from enum import Enum, auto


def callback() -> None:
    pass


class PmsConnection(object):
    def __init__(self) -> None:
        pass

    def Connect(self, type=None) -> None:
        pass

    def Disconnect(self) -> None:
        pass


class RasSeverity(Enum):
    def __init__(self) -> None:
        SeverityAll = auto()


class TelemetryNotificationRequestType(Enum):
    def __init__(self) -> None:
        RequestErrorAll = auto()


class PmsTelemetry():
    def __init__(self, conn) -> None:
        pass

    def SetRASSeverity(RasSeverity) -> None:
        pass

    def RegisterNotificationCallback(callback, TelemetryNotificationRequestType) -> None:
        pass


class PmsConnectionType(Enum):
    def __init__(self) -> None:
        RM_DAEMON = auto()

    def register_pms_notification(self) -> None:
        pass
