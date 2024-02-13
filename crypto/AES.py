import json
from base64 import b64decode, b64encode

from Crypto.Cipher import AES

from util.logger import Logger


def AES_encrypt(key: bytes, data_to_encrypt: str):
    """
    Encrypts data using AES encryption in GCM mode.

    :param key: AES key in byte-format. Key length 128, 192 or 256 bit.
    :param data_to_encrypt:
    :return: A JSON-formatted string containing the AES 'nonce', 'ciphertext', and 'tag'.
    """
    if data_to_encrypt is None:
        return None
    data_to_encrypt_bytes = data_to_encrypt.encode('utf-8')

    # AES nonce, ciphertext and tag
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt_bytes)

    json_keywords = ['nonce', 'ciphertext', 'tag']
    json_values = [b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag)]
    encryption_components = json.dumps(dict(zip(json_keywords, json_values)))
    return encryption_components


def AES_decrypt(key: bytes, data_to_decrypt: dict) -> str:
    """
    Decrypts data using AES encryption.

    :param key: The encryption key
    :param data_to_decrypt: A dictionary containing 'nonce', 'ciphertext', and 'tag'
    :return: The decrypted plaintext
    """
    try:
        json_key_names = ['nonce', 'ciphertext', 'tag']
        json_values = {keyword: b64decode(data_to_decrypt[keyword]) for keyword in json_key_names}

        cipher = AES.new(key, AES.MODE_GCM, nonce=json_values['nonce'])
        plaintext = cipher.decrypt_and_verify(json_values['ciphertext'], json_values['tag'])
        Logger.debug("AES decrypted key: '%s' from: %s", plaintext.decode('utf-8'), data_to_decrypt)
        return plaintext.decode("utf-8")
    except ValueError as e:
        Logger.info(f"AES decryption: {e}")
