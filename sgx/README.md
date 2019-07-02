SGX Token for SoftHSM
=====================

This library is the a SoftHSM Token backed by SGX as a provider for performing
crypto operations within the Trusted Execution Environment.

###  

See “SGX Token for SoftHSM Architecture and API Specification.docx” for
information on what SoftHSM is, what is and how to build a Token library, and
how to use the SGX Token library.

 

### For security issues, please provide a report to:

\- http://www.intel.com/security

 

### Crypto Mechanisms and Modes

Note that some crypto algorithms required by either PKCS\#11 or FIPS have been
deemed insecure by security experts and are unsupported by either the SGX Token
for SoftHSM, or the underlying crypto library, SGX Crypto API Toolkit. These
include, but are not limited to, SHA-1, MD5, DES, GOSTR3410, and GOSTR3411. As
such, these algorithms/modes have been disabled in code within the Token library
(CryptoHandler.cpp) and are denoted as disallowed. Although these mechanisms may
be allowed within the Token library, they are currently unsupported by the
Crypto API Toolkit (v1.3), and if desired for use will require modifications to
both the Token library and the Crypto API Toolkit. It is recommended for users
of either the SGX Token library or Crypto API Toolkit to ensure that secure
versions of crypto algorithms are used to satisfy individual security
requirements.
