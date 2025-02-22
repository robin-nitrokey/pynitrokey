# coding: utf-8

"""
    NetHSM

    All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All <a href=\"https://tools.ietf.org/html/rfc4648#section-4\">base64</a> encoded values are Big Endian.  # noqa: E501

    The version of the OpenAPI document: v1
    Generated by: https://openapi-generator.tech
"""

from datetime import date, datetime  # noqa: F401
import decimal  # noqa: F401
import functools  # noqa: F401
import io  # noqa: F401
import re  # noqa: F401
import typing  # noqa: F401
import typing_extensions  # noqa: F401
import uuid  # noqa: F401

import frozendict  # noqa: F401

from pynitrokey.nethsm.client import schemas  # noqa: F401


class EncryptRequestData(
    schemas.DictSchema
):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """


    class MetaOapg:
        required = {
            "mode",
            "message",
        }
        
        class properties:
        
            @staticmethod
            def mode() -> typing.Type['EncryptMode']:
                return EncryptMode
        
            @staticmethod
            def message() -> typing.Type['Base64']:
                return Base64
        
            @staticmethod
            def iv() -> typing.Type['Base64']:
                return Base64
            __annotations__ = {
                "mode": mode,
                "message": message,
                "iv": iv,
            }
    
    mode: 'EncryptMode'
    message: 'Base64'
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["mode"]) -> 'EncryptMode': ...
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["message"]) -> 'Base64': ...
    
    @typing.overload
    def __getitem__(self, name: typing_extensions.Literal["iv"]) -> 'Base64': ...
    
    @typing.overload
    def __getitem__(self, name: str) -> schemas.UnsetAnyTypeSchema: ...
    
    def __getitem__(self, name: typing.Union[typing_extensions.Literal["mode", "message", "iv", ], str]):
        # dict_instance[name] accessor
        return super().__getitem__(name)
    
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["mode"]) -> 'EncryptMode': ...
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["message"]) -> 'Base64': ...
    
    @typing.overload
    def get_item_oapg(self, name: typing_extensions.Literal["iv"]) -> typing.Union['Base64', schemas.Unset]: ...
    
    @typing.overload
    def get_item_oapg(self, name: str) -> typing.Union[schemas.UnsetAnyTypeSchema, schemas.Unset]: ...
    
    def get_item_oapg(self, name: typing.Union[typing_extensions.Literal["mode", "message", "iv", ], str]):
        return super().get_item_oapg(name)
    

    def __new__(
        cls,
        *args: typing.Union[dict, frozendict.frozendict, ],
        mode: 'EncryptMode',
        message: 'Base64',
        iv: typing.Union['Base64', schemas.Unset] = schemas.unset,
        _configuration: typing.Optional[schemas.Configuration] = None,
        **kwargs: typing.Union[schemas.AnyTypeSchema, dict, frozendict.frozendict, str, date, datetime, uuid.UUID, int, float, decimal.Decimal, None, list, tuple, bytes],
    ) -> 'EncryptRequestData':
        return super().__new__(
            cls,
            *args,
            mode=mode,
            message=message,
            iv=iv,
            _configuration=_configuration,
            **kwargs,
        )

from pynitrokey.nethsm.client.model.base64 import Base64
from pynitrokey.nethsm.client.model.encrypt_mode import EncryptMode
