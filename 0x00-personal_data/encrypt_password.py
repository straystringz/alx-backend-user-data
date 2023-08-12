#!/usr/bin/env python3
"""A_ module for encrypting passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """H_ashes a password using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """C_hecks is a hashed password was formed from the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
