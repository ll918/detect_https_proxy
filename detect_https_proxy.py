#!/usr/local/bin/env python3
"""Detecting https proxy presence.

Detection is done by comparing the sha1 fingerprint of a security certificate
for a web site with a verified fingerprint.
Verified fingerprints from https://www.grc.com/fingerprints.htm
"""

import hashlib
import ssl

https_port = 443
verified_fingerprint = {
    'www.grc.com': '3fc3245c36b389b175ca20c01fc0f1494b7473e6',
    'www.facebook.com': 'a04eafb348c26b15a8c1aa87a333caa3cdeec9c9',
    'www.paypal.com': 'b9c971668c4e377b82bdee9b07f9c191b6ee59de',
    'www.wikipedia.org': '87f5babbd897c579b66af52fd8638b99bd1ce826',
    'twitter.com': '235a79b3270d790505e0bea2cf5c149f9038821b',
    'www.blogger.com': '24c18787dbf8fd23b77077cd8b266adc174ff2a5',
    'www.linkedin.com': 'a33bb54cbc57513f94a3c288a64a02c5f68d4057',
    'www.yahoo.com': '413072f803ce961210e9a45d10da14b0d2d48532',
    'wordpress.com': '1fe2d64111fca8d71b234ffceca86d80de17d94a',
    'www.wordpress.com': '54e089df28538300105dd43764fde7d0f5ed5bc0'}


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
    pem_cert = ssl.get_server_certificate((site, https_port))
    der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
    return der_cert


wrong_fingerprint = 0
for website, ver_fprint in verified_fingerprint.items():
    certificate = get_certificate(website)
    fingerprint = get_cert_fingerprint(certificate)

    if fingerprint == ver_fprint:
        print(website, ': fingerprint ok')
    else:
        wrong_fingerprint += 1
        print(website, ': fingerprint is', fingerprint, 'instead of',
              ver_fprint)

if wrong_fingerprint > 0:
    print()
    print('There might be an HTTPS proxy intercepting your ssl connections. '
          'Check that your verified fingerprints are accurate and up to date. '
          'Then try again.')
else:
    print()
    print('No HTTPS proxy detected.')
