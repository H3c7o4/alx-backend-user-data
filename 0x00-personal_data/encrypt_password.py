#!/usr/bin/env python3
"""
Module for handling hashed password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """

    Args:
      password(str): Password to hash

    Returns:
      A byte string.
    """
    b_password = password.encode()
    hashed = bcrypt.hashpw(b_password, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes,
             password: str) -> bool:
    """

    Args:
      hashed_password: hashed password
      password: provided password

    Returns:
      A boolean
    """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
