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
    'www.grc.com': '3fc3245c36b389b175ca20c01fc0f1494b7473e6',
    'www.facebook.com': '936f912bafad216fa515256e572cdc35a1451aa5',
    'www.paypal.com': 'b9c971668c4e377b82bdee9b07f9c191b6ee59de',
    'www.wikipedia.org': '586684ef773ea0b85f233873cb4610e8d0e08cb3',
    'twitter.com': '235a79b3270d790505e0bea2cf5c149f9038821b',
    'www.linkedin.com': '3a6039e8cee4fb5887b85397898f049820bfe391',
    'www.yahoo.com': '413072f803ce961210e9a45d10da14b0d2d48532',
    'wordpress.com': '1fe2d64111fca8d71b234ffceca86d80de17d94a',
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
    print(
        'There might be an HTTPS proxy intercepting your secured connections.')
    print(
        'Certificates might differ depending of where you are geographically.')
    print(
        'Check that your verified fingerprints are accurate and up to date then try again.')
    print('For more info: https://www.grc.com/fingerprints.htm')
else:
    pass
