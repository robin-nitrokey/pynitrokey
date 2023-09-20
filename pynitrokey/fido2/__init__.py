import time
from typing import Any, Callable, List, Optional, Union

import usb
from fido2.hid import CtapHidDevice

from pynitrokey.exceptions import NoSoloFoundError

# from pynitrokey.fido2 import hmac_secret
from pynitrokey.fido2.client import NKFido2Client


def hot_patch_windows_libusb() -> None:
    # hot patch for windows libusb backend
    olddel = usb._objfinalizer._AutoFinalizedObjectBase.__del__

    def newdel(self):  # type: ignore
        try:
            olddel(self)
        except OSError:
            pass

    usb._objfinalizer._AutoFinalizedObjectBase.__del__ = newdel


# @todo: remove this, HidOverUDP is not available anymore!
def _UDP_InternalPlatformSwitch(
    funcname: str, *args: tuple[Any, Any], **kwargs: dict[Any, Any]
) -> None:
    if funcname == "__init__":
        return HidOverUDP(*args, **kwargs)  # type: ignore
    return getattr(HidOverUDP, funcname)(*args, **kwargs)  # type: ignore


def find(
    solo_serial: Optional[str] = None,
    retries: int = 5,
    raw_device: Optional[CtapHidDevice] = None,
    udp: bool = False,
    pin: Optional[str] = None,
) -> NKFido2Client:

    # @todo: remove this, force_udp_backend is not available anymore!
    if udp:
        force_udp_backend()  # type: ignore

    p = NKFido2Client()

    # This... is not the right way to do it yet
    p.use_u2f()

    for i in range(retries):
        try:
            p.find_device(dev=raw_device, solo_serial=solo_serial, pin=pin)
            return p
        except RuntimeError:
            time.sleep(0.2)

    # return None
    raise NoSoloFoundError("no Nitrokey FIDO2 found")


def find_all() -> List[NKFido2Client]:

    hid_devices = list(CtapHidDevice.list_devices())
    solo_devices = [
        d
        for d in hid_devices
        if (d.descriptor.vid, d.descriptor.pid)
        in [
            # (  1155,  41674),     <- replacing with 0x-notation
            (0x0483, 0xA2CA),  #
            (0x20A0, 0x42B3),  # ...
            (0x20A0, 0x42B1),  # NK FIDO2
            # (0x20A0, 0x42B2),     # NK3
        ]
    ]
    return [find(raw_device=device) for device in solo_devices]


def device_path_to_str(path: Union[bytes, str]) -> str:
    """
    Converts a device path as returned by the fido2 library to a string.

    Typically, the path already is a string.  Only on Windows, a bytes object
    using an ANSI encoding is used instead.  We use the ISO 8859-1 encoding to
    decode the string which should work for all systems.
    """
    if isinstance(path, bytes):
        return path.decode("iso-8859-1", errors="ignore")
    else:
        return path
