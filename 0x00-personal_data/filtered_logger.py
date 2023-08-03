#!/usr/bin/env python3
"""
filtered_logger.py
"""
from typing import List
import re
import logging
from logging import StreamHandler
from os import environ
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters values in incoming log records using filter_datum """
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


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


def get_logger() -> logging.Logger:
    """

    Returns a logging.logger object
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)

    return logger


def get_logger() -> logging.Logger:
    """ Returns a Logger Object """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def main():
    """
    Obtain a database connection using get_db and retrieves all rows
    in the users table and display each row under a filtered format
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cursor.description]

    logger = get_logger()

    for row in cursor:
        str_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(row, field_names))
        logger.info(str_row.strip())

    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
