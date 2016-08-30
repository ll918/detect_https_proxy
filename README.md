# detect_https_proxy
Detecting https proxy by comparing the sha1 fingerprint of a web site security
certificate with an independently verified fingerprint.

If the fingerprints are different it _**might**_ be explained by the presence 
of an https proxy intercepting your HTTPS connections.

This would mean that the HTTPS connection is not secure and should not be
trusted.

This script was inspired by this: https://www.grc.com/fingerprints.htm

## How to run
1. Modify verified_fingerprint by adding/updating websites and fingerprints.
2. From the command line run: python3 detect_https_proxy.py.

## I'm looking for opinion on the code
* Is the code doing what is claimed? Will it actually detect the presence of
an https proxy?
* Did you detect an https proxy on your network with this script? At home,
work, school? 
* I'd love to know if this is actually useful.
    
    
## N.B.
www.blogger.com sometime return alternate certificate with fingerprint: 
f377e4d22b65f816117e28897267ee8fa90e75a8. This appear to be a 
false positive. I need to figure the cause.

Security certificates expires over time. If you have a problem with a
fingerprint check first if your fingerprint list is up to date.
This can be done there: https://www.grc.com/fingerprints.htm

## Disclaimer
This script is a work in progress and in need of independent review to make
sure that it will actually detect an https proxy.