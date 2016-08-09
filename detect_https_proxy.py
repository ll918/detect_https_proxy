#!/usr/local/bin/env python3
# Detecting https proxy by getting the security certificate sha1 fingerprint with grc.com list of verified fingerprints.
# If the digests are different it might be explained by the existence of an https proxy.

import hashlib
import ssl

host = "www.grc.com"
host2 = "www.facebook.com"
host3 = "www.paypal.com"
https_port = 443


def get_cert_fingerprint(certificate):
    h = hashlib.sha1()
    der_cert = ssl.PEM_cert_to_DER_cert(certificate)
    h.update(der_cert)
    digest = h.hexdigest()
    return digest


certificate = ssl.get_server_certificate((host, https_port))
fingerprint = get_cert_fingerprint(certificate)
print(fingerprint)

# todo compare fingerprint with verified fingerprint
