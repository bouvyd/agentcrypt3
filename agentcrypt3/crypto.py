# -*- coding: utf-8 -*-

from __future__ import absolute_import

import base64
import os
import struct
from hashlib import sha256

import paramiko
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers, hashes, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from paramiko import Message, SSHException

from .exceptions import AgentCryptException


class AgentKey(paramiko.AgentKey):
    """Specialization of `paramiko.agent.AgentKey`_ with a few additions for our purposes.

    .. _`paramiko.agent.AgentKey`: http://docs.paramiko.org/en/3.4/api/agent.html#paramiko.agent.AgentKey
    """

    _SUPPORTED_KEY_TYPES = ["ssh-rsa", "ssh-ed25519"]

    def __init__(self, agent: paramiko.Agent, agent_key: paramiko.AgentKey):
        super().__init__(agent, agent_key.asbytes())

    def get_sha256_fingerprint(self) -> bytes:
        """
        SHA256 fingerprint extension from `pull request 1103`_.

        .. _`pull request 1103`: https://github.com/paramiko/paramiko/pull/1103/commits/8e0b7ef85fc72d844dee80688060001a3fba8ad0
        """
        return base64.b64encode(sha256(self.asbytes()).digest())[:-1]

    def get_ssh_signature_blob(self, data: bytes) -> bytes:
        """Signs ``data`` and returns the signature as `bytes`.

        :param data: The `bytes` object to be signed.
        :return: The signature part of the resulting `SSH_AGENT_SIGN_RESPONSE` message as described in the RFCs
                 referenced by the `SSH Agent Protocol draft`_.

        .. _`SSH Agent Protocol draft`: https://tools.ietf.org/id/draft-miller-ssh-agent-00.html#rfc.section.4.5.
        """
        try:
            sig_msg = Message(super().sign_ssh_data(data))  # type: ignore
        except SSHException as sshe:
            raise AgentCryptException(
                "Failed access key '{}'. You probably added it with the confirmation option "
                "(ssh-add -c ..) and did not confirm. (Did you install 'ssh-askpass'?)".format(
                    self.get_sha256_fingerprint().decode()
                )
            ) from sshe

        msg_parts = []
        try:
            for _ in range(0, 2):
                msg_parts.append(sig_msg.get_binary())
        except struct.error as se:
            raise AgentCryptException("Failed to unpack SSH_AGENT_SIGN_RESPONSE from agent.") from se

        # Some sanity checks on the signature message.
        if len(msg_parts) != 2:
            raise AgentCryptException(
                "Got unexpected SSH_AGENT_SIGN_RESPONSE message from agent "
                "({:d} message parts instead of 2).".format(len(msg_parts))
            )

        sig_format = msg_parts[0].decode(errors="replace")
        sig_blob = msg_parts[1]

        if sig_format not in AgentKey._SUPPORTED_KEY_TYPES:
            raise AgentCryptException(
                "Unsupported '{}' key signature in SSH_AGENT_SIGN_RESPONSE response."
                " Only the following key types are supported: '{}'".format(
                    sig_format, "', '".join(AgentKey._SUPPORTED_KEY_TYPES)
                )
            )

        return sig_blob


class SSHAgent(paramiko.Agent):
    """Specialization of `paramiko.agent.Agent`_ which uses :class:`crypto.AgentKey` objects internally.

    .. _`paramiko.agent.Agent`: http://docs.paramiko.org/en/3.4/api/agent.html#paramiko.agent.Agent
    """

    __instance = None

    def __init__(self):
        try:
            super().__init__()
            self.ac_keys = [AgentKey(self, key) for key in super().get_keys()]

            if not self.ac_keys:
                raise AgentCryptException("No keys found in SSH agent.")

        except SSHException as sshe:
            raise AgentCryptException("Failed to connect to SSH agent.") from sshe

    def __del__(self):
        super().close()  # No other reasonable way than __del__(), to ensure close() is called.

    @classmethod
    def get_key(cls, key_fp: bytes | None = None):
        """
        Searches for the specified key in the agent. Creates a new instance of :class:`SSHAgent`, if necessary
        (singleton logic).

        :param key_fp: The SHA256 fingerprint of the key to search for. If ``None``, the first key is returned.
        :return: :class:`crypto.AgentKey` instance, if a key was found, or ``None`` if nothing was found.
        """
        if not cls.__instance:
            cls.__instance = SSHAgent()
        self = cls.__instance

        for key in self.ac_keys:
            if not key_fp or key.get_sha256_fingerprint() == key_fp:
                return key

        return None


class Cipher:
    """
    Provides symmetric encryption with the help of the `pyca/cryptography`_ library.

    .. _`pyca/cryptography`: https://cryptography.io
    """

    # As a loose convention `len` is the name for the length in bytes and `size` for the size in bits in this class.
    NONCE_LEN = 64
    SALT_LEN = 16

    AES_256_CBC = "AES_256_CBC"
    """ Cipher name. """
    AES_128_CBC = "AES_128_CBC"
    """ Cipher name. """
    DES_EDE3_CBC = "DES_EDE3_CBC"

    def __init__(self, cipher_name=None):
        """Creates a new instance that uses the selected cipher.

        :param cipher_name: One of the cipher names exported by the static members above.
        :return: :class:`crypto.Cipher` instance.
        """

        cipher_name = cipher_name if cipher_name else Cipher.AES_256_CBC
        if cipher_name == Cipher.AES_256_CBC:
            self.algorithm = algorithms.AES
            self.block_size: int = algorithms.AES.block_size  # type: ignore
            self.key_size = 256
        # Ciphers for converting legacy containers only. New ones should always be created as AES_256_CBC.
        elif cipher_name == Cipher.AES_128_CBC:
            self.algorithm = algorithms.AES
            self.block_size: int = algorithms.AES.block_size  # type: ignore
            self.key_size = 128
        elif cipher_name == Cipher.DES_EDE3_CBC:
            self.algorithm = algorithms.TripleDES
            self.block_size: int = algorithms.TripleDES.block_size  # type: ignore
            self.key_size = 192
        else:
            raise AgentCryptException("Unsupported cipher '{}'.".format(cipher_name))
        self.cipher_name = cipher_name

    @property
    def get_nonce(self):
        # Convenience method to get a nonce with the preferred length.
        return os.urandom(Cipher.NONCE_LEN)

    @property
    def get_salt(self):
        # Convenience method to get a salt with the preferred length.
        return os.urandom(Cipher.SALT_LEN)

    @staticmethod
    def get_kdf(salt, key_size):
        """
        Returns the preferred Key Derivation Function (KDF) to be used for deriving the secret key from the signature
        returned by :func:`AgentKey.get_ssh_signature_blob`.

        :return: `PBKDF2HMAC`_ instance.

        This is the place to put another KDF, if preferred. An SCrypt example is provided in the code.
        BCrypt would add dependencies, that's why there is no code for it, but it can be added quiet simply.

        .. _`PBKDF2HMAC`: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC
        """
        # return Scrypt(salt=salt, length=key_size // 8, n=2**14, r=8, p=1, backend=default_backend())
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), salt=salt, length=key_size // 8, iterations=100000, backend=default_backend()
        )

    def encrypt(self, data: bytes, password: bytes, salt: bytes):
        """Encrypt data.

        :param data: Cleartext data to encrypt.
        :param password: The password (will be fed to the KDF in use).
        :param salt: The salt (will be fed to the KDF in use).
        :return: `bytes` object with encrypted data.
        """
        kdf = self.get_kdf(salt, self.key_size)
        key = kdf.derive(password)

        iv = os.urandom(self.block_size // 8)
        encryptor = (ciphers.Cipher(self.algorithm(key), modes.CBC(iv), backend=default_backend())).encryptor()

        padder = padding.PKCS7(self.block_size).padder()
        data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data_enc: bytes, password: bytes, salt: bytes) -> bytes:
        """Decrypt data.

        :param data: `bytes` object with encrypted data.
        :param password: The password (will be fed to the KDF in use).
        :param salt: The salt (will be fed to the KDF in use).
        :return: `bytes` object with cleartext data.
        """
        kdf = self.get_kdf(salt, self.key_size)
        key = kdf.derive(password)

        iv_bytes = self.block_size // 8
        iv = data_enc[0:iv_bytes]
        data_enc = data_enc[iv_bytes:]

        unpadder = padding.PKCS7(self.block_size).unpadder()
        decryptor = (ciphers.Cipher(self.algorithm(key), modes.CBC(iv), backend=default_backend())).decryptor()

        try:
            data = decryptor.update(data_enc) + decryptor.finalize()
            return unpadder.update(data) + unpadder.finalize()
        except (ValueError, TypeError):
            # No padding oracle scenario in our usecase, but probably a good habit not to raise with root cause.
            raise AgentCryptException("Decryption failed.") from AgentCryptException("*redacted*")
