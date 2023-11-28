from enum import Enum, auto


class PmsReset(object):
    def __init__(self, conn) -> None:  # type: ignore  # don't have information to type this
        pass

    def ResetRequest(self, sw_device_id):
        return Status.Success


class PmsConnection(object):
    def __init__(self) -> None:
        pass

    def Connect(self, type=None) -> None:  # type: ignore  # don't have information to type this
        pass

    def Disconnect(self) -> None:
        pass


class Status(Enum):
    Success = auto()


class PmsTelemetry():
    def __init__(self, conn) -> None:  # type: ignore  # don't have information to type this
        pass

    def GetMetrics(self) -> None:
        pass


class PmsConnectionType(Enum):
    def __init__(self) -> None:
        RM_DAEMON = auto()
