#!/usr/bin/env python3
"""
Module for encrypting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashes a password using a random salt """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if the provided password matches the hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
