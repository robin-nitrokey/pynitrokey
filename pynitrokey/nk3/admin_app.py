import enum
from enum import Enum
from typing import Optional

from fido2.ctap import CtapError

from pynitrokey.nk3.device import Command, Nitrokey3Device

from .device import VERSION_LEN
from .utils import Version


@enum.unique
class AdminCommand(Enum):
    STATUS = 0x80


class AdminApp:
    def __init__(self, device: Nitrokey3Device) -> None:
        self.device = device

    def _call(
        self,
        command: AdminCommand,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> Optional[bytes]:
        try:
            return self.device._call(
                Command.ADMIN,
                response_len=response_len,
                data=command.value.to_bytes(1, "big") + data,
            )
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                return None
            else:
                raise

    def status(self) -> Optional[int]:
        status = self._call(AdminCommand.STATUS)
        if status is not None:
            if not status:
                raise ValueError("The device returned an empty status")
            return status[0]
        else:
            return None

    def version(self) -> Version:
        reply = self.device._call(Command.VERSION, data=bytes([0x01]))
        if len(reply) == VERSION_LEN:
            version = int.from_bytes(reply, "big")
            return Version.from_int(version)
        else:
            return Version.from_str(reply.decode("utf-8"))
