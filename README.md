# detect_https_proxy
Detecting https proxy by comparing the sha1 fingerprint of a security certificate for a web site with a verified fingerprint.
If the digests are different it might be explained by the existence of an https proxy. This would mean that someone is
eavesdropping on the https port and that your connection is not secure and should not be trusted.

This script was inspired by the following article: https://www.grc.com/fingerprints.htm
