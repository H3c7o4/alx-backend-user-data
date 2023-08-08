#!/usr/bin/env python3
"""
Module for BasicAuth
"""
from api.v1.auth.auth import Auth
import binascii
import base64


class BasicAuth(Auth):
    """Basic Authentication
    """

    def extract_base64_authorization_header(
            self,
            authorization_header: str
            ) -> str:
        """

        Args:
          - authorization_header(string): header content

        Returns:
          - A string
        """
        if authorization_header is None:
            return None
        elif type(authorization_header) != str:
            return None
        elif not(authorization_header.startswith('Basic ')):
            return None
        else:
            value = authorization_header.replace('Basic ', '')
            return value

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
            ) -> str:
        """

        Args:
          - base64_authorization_header(string): base64 authorization

        Returns:
          - a String
        """
        if base64_authorization_header is None:
            return None
        elif type(base64_authorization_header) != str:
            return None

        try:
            data = base64.b64decode(
                    base64_authorization_header,
                    validate=True
                    )
            return data.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
            ) -> (str, str):
        """

        Args:
          - decoded_base64_authorization_header(string): base64 authorization

        Returns:
          - Tuple
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        elif type(decoded_base64_authorization_header) != str:
            return (None, None)
        elif not(':' in decoded_base64_authorization_header):
            return (None, None)
        else:
            li_dec = decoded_base64_authorization_header.split(':')
            return (li_dec[0], li_dec[1])
