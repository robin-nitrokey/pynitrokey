# coding: utf-8

"""
    Generated by: https://github.com/openapi-json-schema-tools/openapi-json-schema-generator
"""

from pynitrokey.nethsm.client.shared_imports.header_imports import *  # pyright: ignore [reportWildcardImportFromLibrary]

from .content.application_x_pem_file import schema as application_x_pem_file_schema


class RequestBody(api_client.RequestBody):


    class ApplicationXPemFileMediaType(api_client.MediaType):
        schema: typing_extensions.TypeAlias = application_x_pem_file_schema.Schema
    content = {
        'application/x-pem-file': ApplicationXPemFileMediaType,
    }
    required = True
