#include "CryptoHandler.h"

#include "KeyHandler.h"
#include "ObjectHandler.h"
#include "Token.h"

#include "CryptoFactory.h"
#include <odd.h>

#include "interface.h"
#include "OSObject.h"
#include "ObjectFunctions.h"

#include <memory>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>


// Encrypt*/Decrypt*() is for Symmetrical ciphers too
static bool isSymMechanism(CK_MECHANISM_PTR mechanism)
{
	if (mechanism == NULL_PTR) return false;

	switch(mechanism->mechanism) {
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
			return true;

// disallowed
		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
		case CKM_DES_ECB:
		case CKM_DES3_ECB:
		case CKM_AES_ECB:
		default:
			return false;
	}
}

// Sign*/Verify*() is for MACs too
static bool isMacMechanism(CK_MECHANISM_PTR mechanism)
{
	if (mechanism == NULL_PTR) return false;

	switch(mechanism->mechanism) {
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
#ifdef WITH_GOST
			case CKM_GOSTR3411_HMAC:
#endif
		case CKM_DES3_CMAC:
		case CKM_AES_CMAC:
			return true;
		default:
			return false;
	}
}

bool isMechanismPermitted(OSObject& key, CK_MECHANISM_PTR mechanism)
{
	OSAttribute attribute = key.getAttribute(CKA_ALLOWED_MECHANISMS);
	std::set<CK_MECHANISM_TYPE> allowed = attribute.getMechanismTypeSetValue();
	if (allowed.empty())
	{
		return true;
	}

	return allowed.find(mechanism->mechanism) != allowed.end();
}

CK_RV MechParamCheckRSAPKCSOAEP(CK_MECHANISM_PTR mechanism)
{
	// This is a programming error
	if (mechanism->mechanism != CKM_RSA_PKCS_OAEP) {
		ERROR_MSG("MechParamCheckRSAPKCSOAEP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}

	if (mechanism->pParameter == NULL_PTR ||
	    mechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
	{
		ERROR_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}

	CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)mechanism->pParameter;
	if (params->hashAlg != CKM_SHA_1)
	{
		ERROR_MSG("hashAlg must be CKM_SHA_1");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->mgf != CKG_MGF1_SHA1)
	{
		ERROR_MSG("mgf must be CKG_MGF1_SHA1");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->source != CKZ_DATA_SPECIFIED)
	{
		ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pSourceData != NULL)
	{
		ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->ulSourceDataLen != 0)
	{
		ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}

static CK_RV getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	unsigned long rsaMinSize, rsaMaxSize;
	unsigned long dsaMinSize, dsaMaxSize;
	unsigned long dhMinSize, dhMaxSize;
#ifdef WITH_ECC
	unsigned long ecdsaMinSize, ecdsaMaxSize;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
	unsigned long ecdhMinSize = 0, ecdhMaxSize = 0;
	unsigned long eddsaMinSize = 0, eddsaMaxSize = 0;
#endif

	if (pInfo == NULL_PTR) return CKR_ARGUMENTS_BAD;

	KeyHandler::AsymAlgoPtr rsa(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA), KeyHandler::recycleAsymAlgo);
	if (rsa != NULL)
	{
		rsaMinSize = rsa->getMinKeySize();
		rsaMaxSize = rsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

	KeyHandler::AsymAlgoPtr dsa(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DSA), KeyHandler::recycleAsymAlgo);
	if (dsa != NULL)
	{
		dsaMinSize = dsa->getMinKeySize();
		// Limitation in PKCS#11
		if (dsaMinSize < 512)
		{
			dsaMinSize = 512;
		}

		dsaMaxSize = dsa->getMaxKeySize();
		// Limitation in PKCS#11
		if (dsaMaxSize > 1024)
		{
			dsaMaxSize = 1024;
		}
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

	KeyHandler::AsymAlgoPtr dh(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::DH), KeyHandler::recycleAsymAlgo);
	if (dh != NULL)
	{
		dhMinSize = dh->getMinKeySize();
		dhMaxSize = dh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

#ifdef WITH_ECC
	KeyHandler::AsymAlgoPtr ecdsa(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA), KeyHandler::recycleAsymAlgo);
	if (ecdsa != NULL)
	{
		ecdsaMinSize = ecdsa->getMinKeySize();
		ecdsaMaxSize = ecdsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}

	KeyHandler::AsymAlgoPtr ecdh(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH), KeyHandler::recycleAsymAlgo);
	if (ecdh != NULL)
	{
		ecdhMinSize = ecdh->getMinKeySize();
		ecdhMaxSize = ecdh->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
#endif

#ifdef WITH_EDDSA
	KeyHandler::AsymAlgoPtr eddsa(CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA), KeyHandler::recycleAsymAlgo);
	if (eddsa != NULL)
	{
		eddsaMinSize = eddsa->getMinKeySize();
		eddsaMaxSize = eddsa->getMaxKeySize();
	}
	else
	{
		return CKR_GENERAL_ERROR;
	}
#endif
	switch (type)
	{
#ifndef WITH_FIPS
// disallowed as insecure
		//case CKM_MD5:
#endif
// disallowed as insecure
		//case CKM_SHA_1:
		//case CKM_SHA224:

		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_HMAC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 512;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
// disallowed as insecure
		//case CKM_SHA_1_HMAC:
		// 	pInfo->ulMinKeySize = 20;
		// 	pInfo->ulMaxKeySize = 512;
		// 	pInfo->flags = CKF_SIGN | CKF_VERIFY;
		// 	break;
		// case CKM_SHA224_HMAC:
		// 	pInfo->ulMinKeySize = 28;
		// 	pInfo->ulMaxKeySize = 512;
		// 	pInfo->flags = CKF_SIGN | CKF_VERIFY;
		// 	break;


		case CKM_SHA256_HMAC:
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 512;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA384_HMAC:
			pInfo->ulMinKeySize = 48;
			pInfo->ulMaxKeySize = 512;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_SHA512_HMAC:
			pInfo->ulMinKeySize = 64;
			pInfo->ulMaxKeySize = 512;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
		case CKM_RSA_X_509:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
			break;
#ifndef WITH_FIPS
// disallowed as insecure
		//case CKM_MD5_RSA_PKCS:
#endif
// disallowed as insecure
		//case CKM_SHA1_RSA_PKCS:
		//case CKM_SHA224_RSA_PKCS:

		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
#endif
// disallowed as insecure
		//case CKM_SHA1_RSA_PKCS_PSS:
		//case CKM_SHA224_RSA_PKCS_PSS:


		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = rsaMinSize;
			pInfo->ulMaxKeySize = rsaMaxSize;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			pInfo->ulMinKeySize = 1;
			pInfo->ulMaxKeySize = 0x80000000;
			pInfo->flags = CKF_GENERATE;
			break;
#ifndef WITH_FIPS
		case CKM_DES_KEY_GEN:
#endif
		case CKM_DES2_KEY_GEN:
		case CKM_DES3_KEY_GEN:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE;
			break;
#ifndef WITH_FIPS
// disallowed as insecure
		//case CKM_DES_ECB:

		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
#endif
// disallowed as insecure
		//case CKM_DES3_ECB:

		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_DES3_CMAC:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_GENERATE;
			break;
// disallowed as insecure
		//case CKM_AES_ECB:

		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
#ifdef WITH_AES_GCM
		case CKM_AES_GCM:
#endif
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;
		case CKM_AES_KEY_WRAP:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 0x80000000;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			pInfo->ulMinKeySize = 1;
			pInfo->ulMaxKeySize = 0x80000000;
			pInfo->flags = CKF_WRAP | CKF_UNWRAP;
			break;
#endif
#ifndef WITH_FIPS
// disallowed as insecure
		//case CKM_DES_ECB_ENCRYPT_DATA:

		case CKM_DES_CBC_ENCRYPT_DATA:
#endif
// disallowed as insecure
		//case CKM_DES3_ECB_ENCRYPT_DATA:

		case CKM_DES3_CBC_ENCRYPT_DATA:

// disallowed as insecure
		//case CKM_AES_ECB_ENCRYPT_DATA:

		case CKM_AES_CBC_ENCRYPT_DATA:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DERIVE;
			break;
		case CKM_AES_CMAC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DSA_PARAMETER_GEN:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DSA:
// disallowed as insecure
		//case CKM_DSA_SHA1:
		//case CKM_DSA_SHA224:


		case CKM_DSA_SHA256:
		case CKM_DSA_SHA384:
		case CKM_DSA_SHA512:
			pInfo->ulMinKeySize = dsaMinSize;
			pInfo->ulMaxKeySize = dsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_DH_PKCS_DERIVE:
			pInfo->ulMinKeySize = dhMinSize;
			pInfo->ulMaxKeySize = dhMaxSize;
			pInfo->flags = CKF_DERIVE;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
#define CKF_EC_COMMOM	(CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
			pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_COMMOM;
			break;
		case CKM_ECDSA:
			pInfo->ulMinKeySize = ecdsaMinSize;
			pInfo->ulMaxKeySize = ecdsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_EC_COMMOM;
			break;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
		case CKM_ECDH1_DERIVE:
			pInfo->ulMinKeySize = ecdhMinSize ? ecdhMinSize : eddsaMinSize;
			pInfo->ulMaxKeySize = ecdhMaxSize ? ecdhMaxSize : eddsaMaxSize;
			pInfo->flags = CKF_DERIVE;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3411:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_GOSTR3411_HMAC:
			// Key size is not in use
			pInfo->ulMinKeySize = 32;
			pInfo->ulMaxKeySize = 512;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_GOSTR3410:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
		case CKM_GOSTR3410_WITH_GOSTR3411:
			// Key size is not in use
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = eddsaMinSize;
			pInfo->ulMaxKeySize = eddsaMaxSize;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_EDDSA:
			pInfo->ulMinKeySize = eddsaMinSize;
			pInfo->ulMaxKeySize = eddsaMaxSize;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;
#endif
		default:
			DEBUG_MSG("The selected mechanism is not supported");
			return CKR_GENERAL_ERROR;
			break;
	}

	return CKR_OK;
}

CK_RV CryptoHandler::getMechanismList(std::vector<token_mechanism_struct>& mechanisms)
{
	// A list with the supported mechanisms
	// 75 for all mechanisms
	// 22 conditional from ECC, FIPS, GOST ...
	
	// 53 total base mechanisms; 20 disabled
	// 33 base supported mechanisms
	
	CK_ULONG nrSupportedMechanisms = 33; 
#ifdef WITH_ECC
	nrSupportedMechanisms += 2;
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
	nrSupportedMechanisms += 1;
#endif
#ifdef WITH_FIPS
	nrSupportedMechanisms -= 9;
#endif
#ifdef WITH_GOST
	nrSupportedMechanisms += 5;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
	nrSupportedMechanisms += 1;
#endif
#ifdef WITH_RAW_PSS
	nrSupportedMechanisms += 1; // CKM_RSA_PKCS_PSS
#endif
#ifdef WITH_AES_GCM
	nrSupportedMechanisms += 1;
#endif
#ifdef WITH_EDDSA
	nrSupportedMechanisms += 2;
#endif

	CK_MECHANISM_TYPE supportedMechanisms[] =
	{
#ifndef WITH_FIPS
// disallowed as insecure
		//CKM_MD5,
#endif
// these are disallowed as insecure
		//CKM_SHA_1,
		//CKM_SHA224,

		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
#ifndef WITH_FIPS
// disallowed as insecure
		//CKM_MD5_HMAC,
#endif

// these are disallowed as insecure
		//CKM_SHA_1_HMAC,
		//CKM_SHA224_HMAC,

		CKM_SHA256_HMAC,
		CKM_SHA384_HMAC,
		CKM_SHA512_HMAC,
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_RSA_PKCS,
		CKM_RSA_X_509,
#ifndef WITH_FIPS
		CKM_MD5_RSA_PKCS,
#endif
// these are disallowed as insecure
		//CKM_SHA1_RSA_PKCS,


		CKM_RSA_PKCS_OAEP,
		//CKM_SHA224_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
#ifdef WITH_RAW_PSS
		CKM_RSA_PKCS_PSS,
#endif
// these are disallowed as insecure
		//CKM_SHA1_RSA_PKCS_PSS,
		//CKM_SHA224_RSA_PKCS_PSS,


		CKM_SHA256_RSA_PKCS_PSS,
		CKM_SHA384_RSA_PKCS_PSS,
		CKM_SHA512_RSA_PKCS_PSS,
		CKM_GENERIC_SECRET_KEY_GEN,
#ifndef WITH_FIPS
// disallowed as insecure
		//CKM_DES_KEY_GEN,
#endif
// disallowed as insecure
		//CKM_DES2_KEY_GEN,
		//CKM_DES3_KEY_GEN,
#ifndef WITH_FIPS
// disallowed as insecure
		//CKM_DES_ECB,
		// CKM_DES_CBC,
		// CKM_DES_CBC_PAD,
		// CKM_DES_ECB_ENCRYPT_DATA,
		// CKM_DES_CBC_ENCRYPT_DATA,
#endif
		// CKM_DES3_ECB,
		// CKM_DES3_CBC,
		// CKM_DES3_CBC_PAD,
		// CKM_DES3_ECB_ENCRYPT_DATA,
		// CKM_DES3_CBC_ENCRYPT_DATA,
		// CKM_DES3_CMAC,
		CKM_AES_KEY_GEN,
		//CKM_AES_ECB,
		CKM_AES_CBC,
		CKM_AES_CBC_PAD,
		CKM_AES_CTR,
#ifdef WITH_AES_GCM
		CKM_AES_GCM,
#endif
		CKM_AES_KEY_WRAP,
#ifdef HAVE_AES_KEY_WRAP_PAD
		CKM_AES_KEY_WRAP_PAD,
#endif
// disallowed as insecure
		//CKM_AES_ECB_ENCRYPT_DATA,
		CKM_AES_CBC_ENCRYPT_DATA,
		CKM_AES_CMAC,
		CKM_DSA_PARAMETER_GEN,
		CKM_DSA_KEY_PAIR_GEN,
		CKM_DSA,
// these are disallowed as insecure
		//CKM_DSA_SHA1,
		//CKM_DSA_SHA224,

		CKM_DSA_SHA256,
		CKM_DSA_SHA384,
		CKM_DSA_SHA512,
		CKM_DH_PKCS_KEY_PAIR_GEN,
		CKM_DH_PKCS_PARAMETER_GEN,
		CKM_DH_PKCS_DERIVE,
#ifdef WITH_ECC
		CKM_EC_KEY_PAIR_GEN,
		CKM_ECDSA,
#endif
#if defined(WITH_ECC) || defined(WITH_EDDSA)
		CKM_ECDH1_DERIVE,
#endif
#ifdef WITH_GOST
		CKM_GOSTR3411,
		CKM_GOSTR3411_HMAC,
		CKM_GOSTR3410_KEY_PAIR_GEN,
		CKM_GOSTR3410,
		CKM_GOSTR3410_WITH_GOSTR3411,
#endif
#ifdef WITH_EDDSA
		CKM_EC_EDWARDS_KEY_PAIR_GEN,
		CKM_EDDSA,
#endif
	};

	CK_RV returnValue = CKR_OK;
	for (CK_ULONG i = 0; i < nrSupportedMechanisms; ++i)
	{
		CK_MECHANISM_TYPE type = supportedMechanisms[i];
		CK_MECHANISM_INFO pInfo;
		CK_RV rv = getMechanismInfo(type, &pInfo);
		if (rv != CKR_OK)
		{
			returnValue = rv;
			continue;
		}
		mechanisms.push_back({ type, pInfo.ulMinKeySize, pInfo.ulMaxKeySize, pInfo.flags });
	}

	return returnValue;
}

static CK_RV UnwrapKeySym(SoftToken& token, OSObject& unwrapKey, CK_MECHANISM_PTR mechanism,
		ByteString& wrapped, ByteString& keydata)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;
	switch(mechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		default:
			return CKR_GENERAL_ERROR;
	}

	KeyHandler::SymAlgoPtr cipher(CryptoFactory::i()->getSymmetricAlgorithm(algo), KeyHandler::recycleSymAlgo);
	if (cipher == NULL) return CKR_GENERAL_ERROR;

	SymmetricKey unwrappingkey;

	if (KeyHandler::getSymmetricKey(token, unwrappingkey, unwrapKey) != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	unwrappingkey.setBitLen(unwrappingkey.getKeyBits().size() * bb);

	// Unwrap the key
	CK_RV rv = CKR_OK;
	if (!cipher->unwrapKey(&unwrappingkey, mode, wrapped, keydata))
		rv = CKR_GENERAL_ERROR;

	return rv;
}

static CK_RV UnwrapKeyAsym(SoftToken& token, OSObject& unwrapKey, CK_MECHANISM_PTR mechanism,
                          ByteString& wrapped, ByteString& keydata)
{
	// Get the symmetric algorithm matching the mechanism
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mode = AsymMech::Unknown;
	switch(mechanism->mechanism) {
		case CKM_RSA_PKCS:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS;
			break;

		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS_OAEP;
			break;

		default:
			return CKR_GENERAL_ERROR;
	}
	KeyHandler::AsymAlgoPtr cipher(CryptoFactory::i()->getAsymmetricAlgorithm(algo), KeyHandler::recycleAsymAlgo);
	if (cipher == NULL) return CKR_GENERAL_ERROR;

	std::unique_ptr<PrivateKey> unwrappingkey(cipher->newPrivateKey());
	if (unwrappingkey == NULL)
	{
		return CKR_HOST_MEMORY;
	}

	switch(mechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (KeyHandler::getRSAPrivateKey(token, *unwrappingkey, unwrapKey) != CKR_OK)
			{
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_GENERAL_ERROR;
	}

	// Unwrap the key
	CK_RV rv = CKR_OK;
	if (!cipher->unwrapKey(unwrappingkey.get(), wrapped, keydata, mode))
		rv = CKR_GENERAL_ERROR;

	return rv;
}

CK_RV CryptoHandler::unwrapKey(SoftToken& token, OSObject& unwrappingKey, OSObject*& newKey,
	                       CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, unsigned long attribute_count,
	                       unsigned char* wrapped_key, unsigned long wrapped_key_len)
{
	CK_RV rv = CKR_OK;
	// Check the mechanism
	switch(mechanism->mechanism)
	{
		case CKM_AES_GCM:
			if (wrapped_key_len != 32)
				return CKR_WRAPPED_KEY_LEN_RANGE;
			break;

		case CKM_AES_CBC:
			if (wrapped_key_len != 16)
				return CKR_WRAPPED_KEY_LEN_RANGE;
			break;

		case CKM_AES_CBC_PAD:
			if (wrapped_key_len != 32)
				return CKR_WRAPPED_KEY_LEN_RANGE;
			break;

#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_CTR:
			if (wrapped_key_len != 16)
				return CKR_WRAPPED_KEY_LEN_RANGE;
			break;

		case CKM_AES_KEY_WRAP:
			if ((wrapped_key_len < 24) || ((wrapped_key_len % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (mechanism->pParameter != NULL_PTR ||
			    mechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			if ((wrapped_key_len < 16) || ((wrapped_key_len % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (mechanism->pParameter != NULL_PTR ||
			    mechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
		case CKM_RSA_PKCS:
			// Input length checks needs to be done later when unwrapping key is known
			break;
		case CKM_RSA_PKCS_OAEP:
			rv = MechParamCheckRSAPKCSOAEP(mechanism);
			if (rv != CKR_OK)
				return rv;
			break;

		default:
			return CKR_GENERAL_ERROR;
	}

	// Check unwrapping key class and type
	if ((mechanism->mechanism == CKM_AES_KEY_WRAP || mechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && unwrappingKey.getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	if (mechanism->mechanism == CKM_AES_KEY_WRAP && unwrappingKey.getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	if (mechanism->mechanism == CKM_AES_KEY_WRAP_PAD && unwrappingKey.getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	if ((mechanism->mechanism == CKM_RSA_PKCS || mechanism->mechanism == CKM_RSA_PKCS_OAEP) && unwrappingKey.getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	if ((mechanism->mechanism == CKM_RSA_PKCS || mechanism->mechanism == CKM_RSA_PKCS_OAEP) && unwrappingKey.getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

	// Check if the unwrapping key can be used for unwrapping
	if (unwrappingKey.getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the unwrap key
	if (!isMechanismPermitted(unwrappingKey, mechanism))
		return CKR_GENERAL_ERROR;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_TRUE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = false;
	rv = ObjectFunctions::extractObjectInformation(templ, attribute_count, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	// Build unwrapped key template
	const CK_ULONG maxAttribs = 32;
	isOnToken = TRUE;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
			{ CKA_CLASS, &objClass, sizeof(objClass) },
			{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
			{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (attribute_count > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < attribute_count; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = templ[i];
		}
	}

	// Apply the unwrap template
	if (unwrappingKey.attributeExists(CKA_UNWRAP_TEMPLATE))
	{
		OSAttribute unwrapAttr = unwrappingKey.getAttribute(CKA_UNWRAP_TEMPLATE);

		if (unwrapAttr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = unwrapAttr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				CK_ATTRIBUTE* attr = NULL;
				for (CK_ULONG i = 0; i < secretAttribsCount; ++i)
				{
					if (it->first == secretAttribs[i].type)
					{
						if (attr != NULL)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						attr = &secretAttribs[i];
						ByteString value;
						it->second.peekValue(value);
						if (attr->ulValueLen != value.size())
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						if (memcmp(attr->pValue, value.const_byte_str(), value.size()) != 0)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
					}
				}
				if (attr == NULL)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
		}
	}

	rv = ObjectHandler::createObject(token, newKey, secretAttribs, secretAttribsCount, OBJECT_OP_UNWRAP);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (newKey == NULL_PTR || !newKey->isValid())
		{
			rv = CKR_FUNCTION_FAILED;
		}
		else if (newKey->startTransaction())
		{
			bool bOK = true;

			// Common Attributes
			bOK = bOK && newKey->setAttribute(CKA_LOCAL, false);

			// Common Secret Key Attributes
			bOK = bOK && newKey->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && newKey->setAttribute(CKA_NEVER_EXTRACTABLE, false);

 			if (bOK)
 				bOK = newKey->commitTransaction();
		}
		else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (newKey && rv != CKR_OK)
		ObjectHandler::destroyObject(newKey);

	return rv;
}

CK_RV CryptoHandler::generateKey(SoftToken& token, OSObject*& key, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ,
		unsigned long count)
{
	// Check the mechanism, only accept DSA and DH parameters
	// and symmetric ciphers
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	switch (mechanism->mechanism)
	{
		case CKM_DSA_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			objClass = CKO_DOMAIN_PARAMETERS;
			keyType = CKK_DH;
			break;
#ifndef WITH_FIPS
		case CKM_DES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES;
			break;
#endif
		case CKM_DES2_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES2;
			break;
		case CKM_DES3_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_DES3;
			break;
		case CKM_AES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_AES;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_GENERIC_SECRET;
			break;
		default:
			return CKR_GENERAL_ERROR;
	}

	// Extract information from the template that is needed to create the object.
	CK_BBOOL isOnToken = CK_TRUE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = true;
	CK_RV rv = ObjectFunctions::extractObjectInformation(templ, count, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
		return rv;

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_DOMAIN_PARAMETERS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (mechanism->mechanism == CKM_DSA_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DSA))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DH_PKCS_PARAMETER_GEN &&
	    (objClass != CKO_DOMAIN_PARAMETERS || keyType != CKK_DH))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DES2_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES2))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DES3_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_DES3))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_AES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_AES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_GENERIC_SECRET))
		return CKR_TEMPLATE_INCONSISTENT;


// NOTE:
// Only care about creating OSObject here, and validating mechanism/template in each specific instance
// No actual key generation is performed within these functions
	switch (mechanism->mechanism)
	{
		case CKM_DSA_PARAMETER_GEN:
			// Generate DSA domain parameters
			rv = KeyHandler::generateDSAParameters(token, templ, count, key, isPrivate);
			break;
		case CKM_DH_PKCS_PARAMETER_GEN:
			// Generate DH domain parameters
			rv = KeyHandler::generateDHParameters(token, templ, count, key, isPrivate);
			break;
		case CKM_DES_KEY_GEN:
			// Generate DES secret key
			rv = KeyHandler::generateDES(token, templ, count, key, isPrivate);
			break;
		case CKM_DES2_KEY_GEN:
			// Generate DES2 secret key
			rv = KeyHandler::generateDES2(token, templ, count, key, isPrivate);
			break;
		case CKM_DES3_KEY_GEN:
			// Generate DES3 secret key
			rv = KeyHandler::generateDES3(token, templ, count, key, isPrivate);
			break;
		case CKM_AES_KEY_GEN:
			// Generate AES secret key
			rv = KeyHandler::generateAES(token, templ, count, key, isPrivate);
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			// Generate generic secret key
			rv = KeyHandler::generateGeneric(token, templ, count, key, isPrivate);
			break;
		default:
			rv = CKR_GENERAL_ERROR;
	}

	if (rv != CKR_OK && key != nullptr)
		ObjectHandler::destroyObject(key);

	return rv;
}

CK_RV CryptoHandler::generateKeyPair(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
		CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
		CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count)
{
	// Check the mechanism, only accept RSA, DSA, EC and DH key pair generation.
	CK_KEY_TYPE keyType;
	switch (mechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			keyType = CKK_RSA;
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			keyType = CKK_DSA;
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			keyType = CKK_DH;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			keyType = CKK_EC;
			break;
#endif
#ifdef WITH_GOST
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			keyType = CKK_GOSTR3410;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			keyType = CKK_EC_EDWARDS;
			break;
#endif
		default:
			return CKR_GENERAL_ERROR;
	}
	CK_CERTIFICATE_TYPE dummy;

	// Extract information from the public key template that is needed to create the object.
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL ispublicKeyOnToken = CK_TRUE;
	CK_BBOOL ispublicKeyPrivate = CK_FALSE;
	bool isPublicKeyImplicit = true;
	CK_RV rv = ObjectFunctions::extractObjectInformation(public_templ, public_templ_count, publicKeyClass,
			keyType, dummy, ispublicKeyOnToken, ispublicKeyPrivate, isPublicKeyImplicit);
	if (rv != CKR_OK)
		return rv;

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (publicKeyClass != CKO_PUBLIC_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (mechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;

	// Extract information from the private key template that is needed to create the object.
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isprivateKeyOnToken = CK_TRUE;
	CK_BBOOL isprivateKeyPrivate = CK_TRUE;
	bool isPrivateKeyImplicit = true;
	rv = ObjectFunctions::extractObjectInformation(private_templ, private_templ_count, privateKeyClass,
			keyType, dummy, isprivateKeyOnToken, isprivateKeyPrivate, isPrivateKeyImplicit);
	if (rv != CKR_OK)
		return rv;

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (privateKeyClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (mechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DSA_KEY_PAIR_GEN && keyType != CKK_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_DH_PKCS_KEY_PAIR_GEN && keyType != CKK_DH)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_GOSTR3410_KEY_PAIR_GEN && keyType != CKK_GOSTR3410)
		return CKR_TEMPLATE_INCONSISTENT;
	if (mechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;


// NOTE:
// Only care about creating OSObject here, and validating mechanism/template in each specific instance
// No actual key generation is performed within these functions
	switch (mechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			// Generate RSA keys
			rv = KeyHandler::generateRSA(token, publicKey, privateKey, public_templ, public_templ_count,
			            private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		case CKM_DSA_KEY_PAIR_GEN:
			// Generate DSA keys
			rv = KeyHandler::generateDSA(token, publicKey, privateKey, public_templ, public_templ_count,
			                 private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		case CKM_EC_KEY_PAIR_GEN:
			// Generate EC keys
			rv = KeyHandler::generateEC(token, publicKey, privateKey, public_templ, public_templ_count,
			                private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			// Generate DH keys
			rv = KeyHandler::generateDH(token, publicKey, privateKey, public_templ, public_templ_count,
					private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		case CKM_GOSTR3410_KEY_PAIR_GEN:
			// Generate GOST keys
			rv = KeyHandler::generateGOST(token, publicKey, privateKey, public_templ, public_templ_count,
			                  private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			// Generate EDDSA keys
			rv = KeyHandler::generateED(token, publicKey, privateKey, public_templ, public_templ_count,
			                private_templ, private_templ_count, ispublicKeyPrivate, isprivateKeyPrivate);
			break;
		default:
			rv = CKR_GENERAL_ERROR;
	}

	if (rv != CKR_OK && (publicKey != nullptr || privateKey != nullptr))
	{
		ObjectHandler::destroyObject(publicKey);
		ObjectHandler::destroyObject(privateKey);
	}

	return rv;
}