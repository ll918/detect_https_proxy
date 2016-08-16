# detect_https_proxy
Detecting https proxy by comparing the sha1 fingerprint of a security
certificate for a web site with a verified fingerprint.

If the fingerprints are different it might be explained by the existence of an
https proxy interfering with your HTTPS connections.

This would mean that the HTTPS connection is not secure and should not be
trusted.

This script was inspired by this: https://www.grc.com/fingerprints.htm
