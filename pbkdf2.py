#!/usr/bin/python

# A simple implementation of pbkdf2 using stock python modules. See RFC2898
# for details. Basically, it derives a key from a password and salt.

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used and modified for any purpose.
#
# 10/13/2020 - Some updates by luke@socially-inept.net to made to make module
#               compatible with Python3 and a little more usable all-around.

from hashlib import sha1
import hmac

from binascii import hexlify, unhexlify
from struct import pack


class PBKDF2(object):
    BLOCKLEN = 20

    # this is what you want to call.
    def __init__(self, password, salt, itercount, keylen, hashfn=sha1):
        self.password = password
        self.salt = salt
        self.itercount = itercount
        self.keylen = keylen
        self.hashfn = hashfn

        # l - number of output blocks to produce
        l = self.keylen / PBKDF2.BLOCKLEN
        if self.keylen % PBKDF2.BLOCKLEN != 0:
            l += 1

        h = hmac.new(self.password, None, self.hashfn)

        T = ""
        for i in range(1, l + 1):
            T += PBKDF2._pbkdf2_f(h, self.salt, self.itercount, i)

        self.key = T[: -(PBKDF2.BLOCKLEN - self.keylen % PBKDF2.BLOCKLEN)]

    @staticmethod
    def _xorstr(a, b):
        if len(a) != len(b):
            raise Exception("xorstr(): lengths differ")

        ret = ''
        for i in range(len(a)):
            ret += chr(ord(a[i]) ^ ord(b[i]))

        return ret

    @staticmethod
    def _prf(h, data):
        hm = h.copy()
        hm.update(data)
        return hm.digest()

    # Helper as per the spec. h is a hmac which has been created seeded with the
    # password, it will be copy()ed and not modified.
    @staticmethod
    def _pbkdf2_f(h, salt, itercount, blocknum):
        U = PBKDF2._prf(h, salt + pack('>i', blocknum))
        T = U

        for i in range(2, itercount + 1):
            U = PBKDF2._prf(h, U)
            T = PBKDF2._xorstr(T, U)

        return T

    def __repr__(self):
        return self.key

    def __str__(self):
        return str(self.key)


def test():
    # test vector from rfc3211
    # password = 'password'
    salt = unhexlify('1234567878563412')
    password = 'All n-entities must communicate with other n-entities via n-1 entiteeheehees'
    itercount = 500
    keylen = 16
    ret = PBKDF2(password, salt, itercount, keylen)
    print("key:      %s" % hexlify(str(ret)))
    print("expected: 6A 89 70 BF 68 C9 2C AE A8 4A 8D F2 85 10 85 86")


if __name__ == '__main__':
    test()
