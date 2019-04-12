import OpenSSL.crypto
from Crypto.Util import asn1

c = OpenSSL.crypto


class Validator:
    def __init__(self):
        pass

    def _get_key(self, key_path):
        st_key = open(key_path, 'rt').read()
        key = c.load_privatekey(c.FILETYPE_ASN1, st_key)
        return key

    def _get_cert(self, cert_path):
        st_cert = open(cert_path, 'rt').read()
        cert = c.load_certificate(c.FILETYPE_ASN1, st_cert)
        return cert

    def validate_by_filenames(self, key_path, cert_path):
        key = self._get_key(key_path)
        cert = self._get_cert(cert_path)

        pub = cert.get_pubkey()

        # Only works for RSA (I think)
        # if pub.type() != c.TYPE_RSA or key.type() != c.TYPE_RSA:
        #     raise Exception('Can only handle RSA keys')

        # This seems to work with public as well
        pub_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, pub)
        priv_asn1 = c.dump_privatekey(c.FILETYPE_ASN1, key)

        # Decode DER
        pub_der = asn1.DerSequence()
        pub_der.decode(pub_asn1)
        priv_der = asn1.DerSequence()
        priv_der.decode(priv_asn1)

        # Get the modulus
        pub_modulus = pub_der[1]
        priv_modulus = priv_der[1]

        if pub_modulus == priv_modulus:
            return True
        else:
            return False
