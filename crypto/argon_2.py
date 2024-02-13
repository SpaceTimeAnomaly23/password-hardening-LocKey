import base64
import os

import argon2


def kdf_argon2(user_password, loc_key, custom_salt: bytes = None):
    """
    Derives a cryptographic key using Argon2 key derivation function. Designed to combine a user-password
    with a LocKey-generated key.

    :param user_password: User password to be hashed and used in key derivation
    :param loc_key: Location-specific key to be combined with the user's password.
    :param custom_salt: Custom salt for hashing. If None, a random salt is generated.
    :return: A tuple containing the derived_key and the salt used for hashing.
    """
    if custom_salt is None:
        custom_salt = os.urandom(18)
        custom_salt = base64.b64encode(custom_salt)

    # Argon2 parameters
    secret = (user_password + loc_key).encode("utf-8")
    time_cost = 1  # Number of iterations
    memory_cost = 2097152  # Amount of memory to use in KiB
    parallelism = 4  # Degree of parallelism
    hash_len = 16  # Desired output hash length in bytes

    # Hash the password with the custom salt using low-level API
    hashed_password = argon2.low_level.hash_secret(
        secret,
        salt=custom_salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=argon2.low_level.Type.ID)

    hashed_password = hashed_password.decode("utf-8")
    hash_parts = hashed_password.split("$")
    password_hash = hash_parts[-1]
    generated_salt = base64.b64decode(hash_parts[4])
    # Key padding and converting to bytes for AES compatability
    while len(password_hash) % 4 != 0:
        password_hash += "="
    derived_key = base64.b64decode(password_hash)
    return derived_key, generated_salt
