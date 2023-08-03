#!/usr/bin/env python3
"""
Module for handling hashed password
"""
import bcrypt


def hash_password(password: str) -> bcrypt:
    """

    Args:
      password(str): Password to hash

    Returns:
      A byte string.
    """
    b_password = password.encode()
    hashed = bcrypt.hashpw(b_password, bcrypt.gensalt())

    return hashed
