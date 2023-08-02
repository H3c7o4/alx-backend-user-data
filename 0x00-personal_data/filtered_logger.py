#!/usr/bin/env python3
"""
filtered_logger.py
"""
from typing import List
import re


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str) -> str:
    """

    Args:
      fields(List[str]): list of strings representing all fields to obfuscate
      redaction(str): string representing by what the field will be obfuscated
      message(str): string representing the log line
      separator(str): string representing by which character is separating
      all fields in the log line (message)

    Returns:
         the log message obfuscated
    """
    for field in fields:
        message = re.sub(f'{field}=(.*?){separator}',
                         f'{field}={redaction}{separator}', message)
    return message
