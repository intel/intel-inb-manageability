from enum import Enum, auto


class PmsReset(object):
    def __init__(self, conn):
        pass

    def ResetRequest(self, sw_device_id):
        return Status.Success


class PmsConnection(object):
    def __init__(self):
        pass

    def Connect(self, type=None):
        pass

    def Disconnect(self):
        pass


class Status(Enum):
    Success = auto()


class PmsTelemetry():
    def __init__(self, conn):
        pass

    def GetMetrics(self):
        pass

class PmsConnectionType(Enum):
    def __init__(self):
        RM_DAEMON = auto()