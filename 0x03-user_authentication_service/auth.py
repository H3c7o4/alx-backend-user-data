#!/usr/bin/env python3
"""
Module for _hash_password
"""
import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
from typing import Union

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """

    Args:
      - password(String): Password of a user

    Returns:
      - A hashed password in bytes
    """
    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)

    return hashed_password


def _generate_uuid() -> str:
    """This function returns a string representation of a new UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """

        Args:
          - email(String): email of the user
          - password(String): password of the user

        Returns:
          - The user registered
        """
        try:
            is_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hsh_pwd = _hash_password(password)
            user = self._db.add_user(email, hsh_pwd)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """

        Args:
          - email(String): email of the user
          - password(String): password of the user

        Returns:
          - True if the password match, false otherwise
        """
        try:
            user = self._db.find_user_by(email=email)

            if user:
                b_password = password.encode('utf-8')
                return bcrypt.checkpw(b_password, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """

        Args:
          - email(String): email of the user

        Returns:
          - The session_id as a string
        """
        try:
            user = self._db.find_user_by(email=email)

            if user:
                session_id = _generate_uuid()
                self._db.update_user(user_id=user.id, session_id=session_id)
                return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """

        Args:
          - session_id(Str): session_id of the user

        Returns:
          - The associated user or None
        """
        try:
            user = self._db.find_user_by(session_id=session_id)

            if user.session_id:
                return user
            return None
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy a user's session_id by his id in the database

        Args:
          - user_id(Integer): user's Id

        Returns:
          - None
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user_id=user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """

        Args:
          - email(String): user's email

        Returns:
          - A token as a string
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user_id=user.id, reset_token=token)

            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """

        Args:
          - reset_token(String): the reset token
          - password(String): password user

        Returns:
          - None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            h_password = _hash_password(password)
            self._db.update_user(user_id=user.id,
                                 hashed_password=h_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
