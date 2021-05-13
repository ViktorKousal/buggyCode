# Credits: https://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
# Credits: https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm

import hmac
import base64
import struct
import hashlib
import time


def get_hotp(key, counter, n_digits):
    """
    Computes HOTP value according to RFC 4226 https://www.ietf.org/rfc/rfc4226.txt
    @param key: The pre-shared key in a form of base32 string (arbitrary length)
    @param counter: The counter used to compute the one-time password
    @param n_digits: How many digits should the resulting decimal code have
    """
    # Decodes the secret key from base32 to bytes
    key = base64.b32decode(key, casefold=True)

    # Encodes the counter into bytes
    c = counter.to_bytes(8, byteorder="big", signed=False)

    # Computes HMAC(key, counter) with SHA-1 as the underlying func
    mac = hmac.new(key, c, "sha1").digest()

    # Computes 4 most significant bits of mac, written in decimal
    i = mac[-1] & 0x0F

    # Takes 31 most significant bits out of 4 bytes in MAC that start at offset i
    # Taking 31 bits effectively gets rid of the sign bit, while the integer still fits 4 bytes.
    # This is desired to remove the ambiguity caused by different implementations on different platforms
    truncated = int.from_bytes(
        mac[i: i + 4], byteorder="big", signed=False) & 0x7FFFFFFF

    # Modulo the desired number of digits
    return truncated % (10 ** n_digits)


def main():
    token = get_hotp('JBSWY3DPEHPK3PXP'.lower(),
                     int(time.time()) // 30, n_digits=6)
    print(str(token).zfill(6))


if __name__ == "__main__":
    main()