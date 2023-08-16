#!/usr/bin/env python3
"""
Module for _hash_password
"""
import bcrypt


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
