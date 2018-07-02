#!/usr/local/bin/env python3
"""Detecting https proxy presence.

Detection is done by comparing the sha1 fingerprint of a security certificate
for a web site with a verified fingerprint.
Verified fingerprints from https://www.grc.com/fingerprints.htm
"""
import hashlib
import ssl
import sys
from collections import OrderedDict

https_port = 443
verified_fingerprint = {
    'www.grc.com': '159a76c5aef4901579e6a49996c1d6a1d93b0743',
    'www.facebook.com': 'bd258c1f62a4a6d9cf7d9812d22e2ff57e84fb36',
    'www.paypal.com': 'bb20b03ffb93e177ff23a7438949601a41aec61c',
    'www.wikipedia.org': '4b3ed6b6a2c755e85684beb1426bb034a6fbac24',
    'twitter.com': '265c85f65b044dc830645c6fb9cfa7d28f28bc1b',
    'www.linkedin.com': '6284f144407cfcbfe3079c59e2753a1e100c2986',
    'www.yahoo.com': 'ae699d5ebddce6ed574111262f19bb18efbe73b0',
    'wordpress.com': '791a83832120f66d9d1e775fed8916fc8ea0e0c3',
    'www.wordpress.com': '54e089df28538300105dd43764fde7d0f5ed5bc0'}

ver_fing_sorted = OrderedDict(
    sorted(verified_fingerprint.items(), key=lambda t: t[0]))


def get_cert_fingerprint(certificate):
    """get a secure certificate in DER format and return a sha1 digest string
    used as a fingerprint
    """

    h = hashlib.sha1()
    h.update(certificate)
    digest = h.hexdigest()
    return digest


def get_certificate(site):
    """get a web site and return a secure certificate in DER format"""

    der_cert = b''
    try:
        pem_cert = ssl.get_server_certificate((site, https_port))
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
    except:
        print("Unexpected error:", sys.exc_info()[0],
              'retrieving certificate from', site)
    return der_cert


wrong_fingerprint = 0
for website, ver_fprint in ver_fing_sorted.items():
    certificate = get_certificate(website)
    if certificate != b'':
        fingerprint = get_cert_fingerprint(certificate)
        if fingerprint == ver_fprint:
            print(website, ': fingerprint ok')
        else:
            wrong_fingerprint += 1
            print(website, ': fingerprint is', fingerprint, 'instead of',
                  ver_fprint)

if wrong_fingerprint > 0:
    print()
    print('There might be an HTTPS proxy intercepting your connections.')
    print('Certificates might differ depending of your location.')
    print('Check your verified fingerprints accuracy then try again.')
    print('For more info: https://www.grc.com/fingerprints.htm')
