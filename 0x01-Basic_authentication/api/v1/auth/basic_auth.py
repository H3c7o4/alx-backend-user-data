#!/usr/bin/env python3
"""
Module for BasicAuth
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import Tuple, TypeVar
import binascii
import base64
import re


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
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
            ) -> TypeVar('User'):
        """

        Args:
          - user_email(string): email of the user
          - user_pwd(string): password of the user

        Returns:
          - User
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
