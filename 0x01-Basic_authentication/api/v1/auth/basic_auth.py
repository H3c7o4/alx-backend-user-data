#!/usr/bin/env python3
"""
Module for BasicAuth
"""
from api.v1.auth.auth import Auth


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
