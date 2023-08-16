#!/usr/bin/env python3
"""
Module for _hash_password
"""
import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
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
