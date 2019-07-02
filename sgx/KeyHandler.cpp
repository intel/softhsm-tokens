#include "KeyHandler.h"

#include "Token.h"
#include "P11Attributes.h"
#include "ObjectHandler.h"

#include <OSObject.h>
#include <ByteString.h>
#include <DerUtil.h>

#include <RSAParameters.h>
#include <DSAParameters.h>
#include <DHParameters.h>
#include <ECParameters.h>
#include <DESKey.h>
#include <AESKey.h>
#include <AsymmetricAlgorithm.h>

#include <DSAPublicKey.h>
#include <DSAPrivateKey.h>
#include <DHPublicKey.h>
#include <DHPrivateKey.h>
#include <ECPublicKey.h>
#include <ECPrivateKey.h>
#include <EDPublicKey.h>
#include <EDPrivateKey.h>
#include <GOSTPublicKey.h>
#include <GOSTPrivateKey.h>
#include <SymmetricKey.h>
#include <RSAPublicKey.h>
#include <RSAPrivateKey.h>

CK_RV KeyHandler::generateDSAParameters(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	// Extract desired parameter information
	size_t bitLen = 0;
	size_t qLen = 0;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_PRIME_BITS:
				if (templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)templ[i].pValue;
				break;
			case CKA_SUB_PRIME_BITS:
				if (templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_SUB_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				qLen = *(CK_ULONG*)templ[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// No real choice for CKA_SUB_PRIME_BITS
	if ((qLen != 0) &&
	    (((bitLen >= 2048) && (qLen != 256)) ||
	     ((bitLen < 2048) && (qLen != 160))))
	{
		INFO_MSG("CKA_SUB_PRIME_BITS is ignored");
	}

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DSA;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
			{ CKA_CLASS, &objClass, sizeof(objClass) },
			{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
			{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};

	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				paramsAttribs[paramsAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, paramsAttribs, paramsAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_PARAMETER_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateDHParameters(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	// Extract desired parameter information
	size_t bitLen = 0;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_PRIME_BITS:
				if (templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_PRIME_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)templ[i].pValue;
				break;
			default:
				break;
		}
	}

	// CKA_PRIME_BITS must be specified
	if (bitLen == 0)
	{
		INFO_MSG("Missing CKA_PRIME_BITS in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	CK_RV rv = CKR_OK;

	// Create the domain parameter object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_DOMAIN_PARAMETERS;
	CK_KEY_TYPE keyType = CKK_DH;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE paramsAttribs[maxAttribs] = {
			{ CKA_CLASS, &objClass, sizeof(objClass) },
			{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
			{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG paramsAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - paramsAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				paramsAttribs[paramsAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, paramsAttribs, paramsAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_PARAMETER_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateDES(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	// Extract desired parameter information
	bool checkValue = true;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_CHECK_VALUE:
				if (templ[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
			{ CKA_CLASS, &objClass, sizeof(objClass) },
			{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
			{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, keyAttribs, keyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES_KEY_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = key->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && key->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = key->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && key->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;

}

CK_RV KeyHandler::generateDES2(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	// Extract desired parameter information
	bool checkValue = true;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_CHECK_VALUE:
				if (templ[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES2;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, keyAttribs, keyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES2_KEY_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = key->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && key->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = key->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && key->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateDES3(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	bool checkValue = true;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_CHECK_VALUE:
				if (templ[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_DES3;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, keyAttribs, keyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DES3_KEY_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = key->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && key->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = key->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && key->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateAES(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	CK_RV rv = CKR_OK;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_VALUE_LEN:
				if (templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)templ[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (templ[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// keyLen must be 16, 24, or 32
	if (keyLen != 16 && keyLen != 24 && keyLen != 32)
	{
		INFO_MSG("bad AES key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};

	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (count > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, keyAttribs, keyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_AES_KEY_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = key->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && key->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = key->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && key->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateGeneric(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate)
{
	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < count; i++)
	{
		switch (templ[i].type)
		{
			case CKA_VALUE_LEN:
				if (templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)templ[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (templ[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Check keyLen
	if (keyLen < 1 || keyLen > 0x8000000)
	{
		INFO_MSG("bad generic key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	CK_RV rv = CKR_OK;

	// Create the secret key object
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = TRUE;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	if (count > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < count && rv == CKR_OK; ++i)
	{
		switch (templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = templ[i];
				break;
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, key, keyAttribs, keyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		if (key == NULL_PTR || !key->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (key->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && key->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_GENERIC_SECRET_KEY_GEN;
			bOK = bOK && key->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = key->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && key->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = key->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && key->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	return rv;
}

CK_RV KeyHandler::generateRSA(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
                CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
                CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
		        CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information: bitlen and public exponent
	size_t bitLen = 0;
	ByteString exponent("010001");
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_MODULUS_BITS:
				if (public_templ[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_MODULUS_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)public_templ[i].pValue;
				break;
			case CKA_PUBLIC_EXPONENT:
				exponent = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// CKA_MODULUS_BITS must be specified to be able to generate a key pair.
	if (bitLen == 0) {
		INFO_MSG("Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_RSA;
		CK_BBOOL isPublicKeyOnToken = TRUE;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
				{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
				{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
				{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (public_templ_count > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
		{
			switch (public_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PUBLIC_EXPONENT:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs,
					publicKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (publicKey == NULL_PTR || !publicKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (publicKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = publicKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && publicKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_RSA;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs,
					privateKeyAttribsCount ,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// RSA Private Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				ByteString privateExponent;
				ByteString prime1;
				ByteString prime2;
				ByteString exponent1;
				ByteString exponent2;
				ByteString coefficient;
			
				bOK = bOK && privateKey->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && privateKey->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				bOK = bOK && privateKey->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
				bOK = bOK && privateKey->setAttribute(CKA_PRIME_1, prime1);
				bOK = bOK && privateKey->setAttribute(CKA_PRIME_2, prime2);
				bOK = bOK && privateKey->setAttribute(CKA_EXPONENT_1,exponent1);
				bOK = bOK && privateKey->setAttribute(CKA_EXPONENT_2, exponent2);
				bOK = bOK && privateKey->setAttribute(CKA_COEFFICIENT, coefficient);

				if (bOK)
					bOK = privateKey->commitTransaction();
				else
					privateKey->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

CK_RV KeyHandler::generateDSA(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
				CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
                CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
                CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			case CKA_SUBPRIME:
				subprime = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || subprime.size() == 0 || generator.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE publicKeyType = CKK_DSA;
	CK_BBOOL isPublicKeyOnToken = TRUE;
	CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
	};
	CK_ULONG publicKeyAttribsCount = 4;

	// Add the additional
	if (public_templ_count > (maxAttribs - publicKeyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
	{
		switch (public_templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs, publicKeyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied by the key generation to the object
	if (rv == CKR_OK)
	{
		if (publicKey == NULL_PTR || !publicKey->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DSA;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};

		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs,
					privateKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DSA_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				if (bOK)
					bOK = privateKey->commitTransaction();
				else
					privateKey->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

CK_RV KeyHandler::generateEC(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
					CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
					CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
					CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC;
		CK_BBOOL isPublicKeyOnToken = TRUE;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
				{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
				{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
				{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (public_templ_count > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
		{
			switch (public_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs,
					publicKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (publicKey == NULL_PTR || !publicKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (publicKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = publicKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && publicKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs,
					privateKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				if (bOK)
					bOK = privateKey->commitTransaction();
				else
					privateKey->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

CK_RV KeyHandler::generateDH(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
					CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
					CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
					CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information
	ByteString prime;
	ByteString generator;
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_PRIME:
				prime = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			case CKA_BASE:
				generator = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (prime.size() == 0 || generator.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Extract optional bit length
	size_t bitLen = 0;
	for (CK_ULONG i = 0; i < private_templ_count; i++)
	{
		switch (private_templ[i].type)
		{
			case CKA_VALUE_BITS:
				bitLen = *(CK_ULONG*)private_templ[i].pValue;
				break;
			default:
				break;
		}
	}

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE publicKeyType = CKK_DH;
	CK_BBOOL isPublicKeyOnToken = TRUE;
	CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
	};
	CK_ULONG publicKeyAttribsCount = 4;

	// Add the additional
	if (public_templ_count > (maxAttribs - publicKeyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
	{
		switch (public_templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs,
				publicKeyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied by the key generation to the object
	if (rv == CKR_OK)
	{
		if (publicKey == NULL_PTR || !publicKey->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_DH;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs,
					privateKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_DH_PKCS_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

CK_RV KeyHandler::generateGOST(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
					CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
					CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
					CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information
	ByteString param_3410;
	ByteString param_3411;
	ByteString param_28147;
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_GOSTR3410_PARAMS:
				param_3410 = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			case CKA_GOSTR3411_PARAMS:
				param_3411 = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			case CKA_GOST28147_PARAMS:
				param_28147 = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (param_3410.size() == 0 || param_3411.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE publicKeyType = CKK_GOSTR3410;
	CK_BBOOL isPublicKeyOnToken = TRUE;
	CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
	};
	CK_ULONG publicKeyAttribsCount = 4;

	// Add the additional
	if (public_templ_count  > (maxAttribs - publicKeyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	
	for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
	{
		switch (public_templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs, publicKeyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied by the key generation to the object
	if (rv == CKR_OK)
	{
		if (publicKey == NULL_PTR || !publicKey->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_GOSTR3410;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs, privateKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				if (bOK)
					bOK = privateKey->commitTransaction();
				else
					privateKey->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

CK_RV KeyHandler::generateED(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
					CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
					CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
					CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate)
{
	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < public_templ_count; i++)
	{
		switch (public_templ[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)public_templ[i].pValue, public_templ[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters

	CK_RV rv = CKR_OK;
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE publicKeyType = CKK_EC_EDWARDS;
	CK_BBOOL isPublicKeyOnToken = TRUE;
	CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
	};
	CK_ULONG publicKeyAttribsCount = 4;

	// Add the additional
	if (public_templ_count > (maxAttribs - publicKeyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < public_templ_count && rv == CKR_OK; ++i)
	{
		switch (public_templ[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				publicKeyAttribs[publicKeyAttribsCount++] = public_templ[i];
		}
	}

	if (rv == CKR_OK)
		rv = ObjectHandler::createObject(token, publicKey, publicKeyAttribs, publicKeyAttribsCount, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied by the key generation to the object
	if (rv == CKR_OK)
	{
		if (publicKey == NULL_PTR || !publicKey->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (publicKey->startTransaction()) {
			bool bOK = true;

			// Common Key Attributes
			bOK = publicKey->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;
			bOK = bOK && publicKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC_EDWARDS;
		CK_BBOOL isPrivateKeyOnToken = TRUE;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
				{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
				{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
				{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
				{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (private_templ_count > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < private_templ_count && rv == CKR_OK; ++i)
		{
			switch (private_templ[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = private_templ[i];
			}
		}

		if (rv == CKR_OK)
			rv = ObjectHandler::createObject(token, privateKey, privateKeyAttribs, privateKeyAttribsCount, OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			if (privateKey == NULL_PTR || !privateKey->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (privateKey->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = privateKey->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;
				bOK = bOK && privateKey->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = privateKey->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && privateKey->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = privateKey->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && privateKey->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				if (bOK)
					bOK = privateKey->commitTransaction();
				else
					privateKey->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	return rv;
}

bool KeyHandler::getPlainCKV(SymmetricKey* key, CK_KEY_TYPE keyType, size_t& byteLen, ByteString& plainKCV)
{
	bool bOK = true;
	// Get the KCV
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			key->setBitLen(byteLen * 8);
			plainKCV = key->getKeyCheckValue();
			break;
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
			key->setBitLen(byteLen * 7);
			plainKCV = static_cast<DESKey*>(key)->getKeyCheckValue();
			break;
		case CKK_AES:
			key->setBitLen(byteLen * 8);
			plainKCV = static_cast<AESKey*>(key)->getKeyCheckValue();
			break;
		default:
			bOK = false;
			break;
	}

	return bOK;
}

CK_RV KeyHandler::getSymmetricKey(SoftToken& token, SymmetricKey& skey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	ByteString keybits;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		if (!token.decrypt(key.getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key.getByteStringValue(CKA_VALUE);
	}

	skey.setKeyBits(keybits);

	return CKR_OK;
}

CK_RV KeyHandler::getRSAPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// RSA Public Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	} else
	{
		modulus = key.getByteStringValue(CKA_MODULUS);
		publicExponent = key.getByteStringValue(CKA_PUBLIC_EXPONENT);
	}

	auto& rsaKey = static_cast<RSAPublicKey&>(publicKey);

	rsaKey.setN(modulus);
	rsaKey.setE(publicExponent);

	return CKR_OK;
}

CK_RV KeyHandler::getRSAPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	// since we don't encrypt session objects right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIVATE_EXPONENT), privateExponent);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIME_1), prime1);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIME_2), prime2);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EXPONENT_1), exponent1);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EXPONENT_2), exponent2);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_COEFFICIENT), coefficient);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key.getByteStringValue(CKA_MODULUS);
		publicExponent = key.getByteStringValue(CKA_PUBLIC_EXPONENT);
		privateExponent = key.getByteStringValue(CKA_PRIVATE_EXPONENT);
		prime1 = key.getByteStringValue(CKA_PRIME_1);
		prime2 = key.getByteStringValue(CKA_PRIME_2);
		exponent1 =  key.getByteStringValue(CKA_EXPONENT_1);
		exponent2 = key.getByteStringValue(CKA_EXPONENT_2);
		coefficient = key.getByteStringValue(CKA_COEFFICIENT);
	}

	auto& rsaKey = static_cast<RSAPrivateKey&>(privateKey);

	rsaKey.setN(modulus);
	rsaKey.setE(publicExponent);
	rsaKey.setD(privateExponent);
	rsaKey.setP(prime1);
	rsaKey.setQ(prime2);
	rsaKey.setDP1(exponent1);
	rsaKey.setDQ1(exponent2);
	rsaKey.setPQ(coefficient);

	return CKR_OK;
}

bool KeyHandler::setRSAPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber)
{

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	
	bool bOK = true;
	bOK = bOK && key.setAttribute(CKA_MODULUS, modulus);
	bOK = bOK && key.setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
	bOK = bOK && key.setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
	bOK = bOK && key.setAttribute(CKA_PRIME_1, prime1);
	bOK = bOK && key.setAttribute(CKA_PRIME_2, prime2);
	bOK = bOK && key.setAttribute(CKA_EXPONENT_1,exponent1);
	bOK = bOK && key.setAttribute(CKA_EXPONENT_2, exponent2);
	bOK = bOK && key.setAttribute(CKA_COEFFICIENT, coefficient);

	return bOK;
}

CK_RV KeyHandler::getDSAPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// DSA Public Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	// since we don't encrypt session objects right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_SUBPRIME), subprime);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key.getByteStringValue(CKA_PRIME);
		subprime = key.getByteStringValue(CKA_SUBPRIME);
		generator = key.getByteStringValue(CKA_BASE);
		value = key.getByteStringValue(CKA_VALUE);
	}

	auto& dsaKey = static_cast<DSAPublicKey&>(publicKey);

	dsaKey.setP(prime);
	dsaKey.setQ(subprime);
	dsaKey.setG(generator);
	dsaKey.setY(value);

	return CKR_OK;
}

CK_RV KeyHandler::getDSAPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_SUBPRIME), subprime);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key.getByteStringValue(CKA_PRIME);
		subprime = key.getByteStringValue(CKA_SUBPRIME);
		generator = key.getByteStringValue(CKA_BASE);
		value = key.getByteStringValue(CKA_VALUE);
	}

	auto& dsaKey = static_cast<DSAPrivateKey&>(privateKey);

	dsaKey.setP(prime);
	dsaKey.setQ(subprime);
	dsaKey.setG(generator);
	dsaKey.setX(value);

	return CKR_OK;
}

bool KeyHandler::setDSAPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber)
{
	// DSA Private Key Attributes
	ByteString prime;
	ByteString subprime;
	ByteString generator;
	ByteString value;

	bool bOK = true;
	bOK = bOK && key.setAttribute(CKA_PRIME, prime);
	bOK = bOK && key.setAttribute(CKA_SUBPRIME, subprime);
	bOK = bOK && key.setAttribute(CKA_BASE, generator);
	bOK = bOK && key.setAttribute(CKA_VALUE, value);

	return bOK;
}

CK_RV KeyHandler::getDHPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// DH Private Key Attributes
	ByteString prime;
	ByteString generator;
	ByteString value;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_PRIME), prime);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_BASE), generator);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		prime = key.getByteStringValue(CKA_PRIME);
		generator = key.getByteStringValue(CKA_BASE);
		value = key.getByteStringValue(CKA_VALUE);
	}

	auto& dhKey = static_cast<DHPrivateKey&>(privateKey);

	dhKey.setP(prime);
	dhKey.setG(generator);
	dhKey.setX(value);

	return CKR_OK;
}

bool KeyHandler::setDHPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber)
{
	bool bOK = true;
	ByteString prime;
	ByteString generator;
	ByteString value;
	bOK = bOK && key.setAttribute(CKA_PRIME, prime);
	bOK = bOK && key.setAttribute(CKA_BASE, generator);
	bOK = bOK && key.setAttribute(CKA_VALUE, value);

	return bOK;
}

CK_RV KeyHandler::getECPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// EC Public Key Attributes
	ByteString group;
	ByteString point;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_POINT), point);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key.getByteStringValue(CKA_EC_PARAMS);
		point = key.getByteStringValue(CKA_EC_POINT);
	}

	auto& ecKey = static_cast<ECPublicKey&>(publicKey);

	ecKey.setEC(group);
	ecKey.setQ(point);

	return CKR_OK;
}

CK_RV KeyHandler::getECPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key.getByteStringValue(CKA_EC_PARAMS);
		value = key.getByteStringValue(CKA_VALUE);
	}

	auto& ecKey = static_cast<ECPrivateKey&>(privateKey);

	ecKey.setEC(group);
	ecKey.setD(value);

	return CKR_OK;
}

bool KeyHandler::setECPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber)
{
	bool bOK = true;
	ByteString group;
	ByteString value;
	bOK = bOK && key.setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key.setAttribute(CKA_VALUE, value);

	return bOK;
}

CK_RV KeyHandler::getEDPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// EC Public Key Attributes
	ByteString group;
	ByteString value;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_POINT), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key.getByteStringValue(CKA_EC_PARAMS);
		value = key.getByteStringValue(CKA_EC_POINT);
	}

	auto& edKey = static_cast<EDPublicKey&>(publicKey);

	edKey.setEC(group);
	edKey.setA(value);

	return CKR_OK;
}

CK_RV KeyHandler::getEDPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// EDDSA Private Key Attributes
	ByteString group;
	ByteString value;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key.getByteStringValue(CKA_EC_PARAMS);
		value = key.getByteStringValue(CKA_VALUE);
	}

	auto& edKey = static_cast<EDPrivateKey&>(privateKey);

	edKey.setEC(group);
	edKey.setK(value);

	return CKR_OK;
}

CK_RV KeyHandler::getGOSTPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key)
{
	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// GOST Public Key Attributes
	ByteString point;
	ByteString param;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), point);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_GOSTR3410_PARAMS), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		point = key.getByteStringValue(CKA_VALUE);
		param = key.getByteStringValue(CKA_GOSTR3410_PARAMS);
	}

	auto& gostKey = static_cast<GOSTPublicKey&>(publicKey);

	gostKey.setQ(point);
	gostKey.setEC(param);

	return CKR_OK;
}

CK_RV KeyHandler::getGOSTPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key)
{
	bool isKeyPrivate = key.getBooleanValue(CKA_PRIVATE, false);
	bool isKeyOnToken = key.getBooleanValue(CKA_TOKEN, true);

	// GOST Private Key Attributes
	ByteString value;
	ByteString param;
	// since session objects are not encrypted right now
	if (isKeyPrivate && isKeyOnToken)
	{
		bool bOK = true;
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_VALUE), value);
		bOK = bOK && token.decrypt(key.getByteStringValue(CKA_GOSTR3410_PARAMS), param);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key.getByteStringValue(CKA_VALUE);
		param = key.getByteStringValue(CKA_GOSTR3410_PARAMS);
	}

	auto& gostKey = static_cast<GOSTPrivateKey&>(privateKey);

	gostKey.setD(value);
	gostKey.setEC(param);

	return CKR_OK;
}

bool KeyHandler::setGOSTPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber)
{
	bool bOK = true;
	ByteString value;
	ByteString param_a;
	bOK = bOK && key.setAttribute(CKA_VALUE, value);
	bOK = bOK && key.setAttribute(CKA_GOSTR3410_PARAMS, "");

	return bOK;
}

CK_RV KeyHandler::getDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, const ByteString& pubData)
{
	auto& dhPubKey = static_cast<DHPublicKey&>(publicKey);
	auto& dhPrivKey = static_cast<DHPrivateKey&>(privateKey);

	dhPubKey.setP(dhPrivKey.getP());
	dhPubKey.setG(dhPrivKey.getG());

	// Set value
	dhPubKey.setY(pubData);

	return CKR_OK;
}

CK_RV KeyHandler::getECDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, ByteString pubData)
{
	auto& ecPubKey = static_cast<ECPublicKey&>(publicKey);
	auto& ecPrivKey = static_cast<ECPrivateKey&>(privateKey);

	// Copy Domain Parameters from Private Key
	ecPubKey.setEC(ecPrivKey.getEC());

	size_t len = pubData.size();
	size_t controlOctets = 2;
	if (len == 32 || len == 65 || len == 97 || len == 133)
	{
		// Raw: Length matches the public key size of:
		// EDDSA: X25519
		// ECDSA: P-256, P-384, or P-521
		controlOctets = 0;
	}
	else if (len < controlOctets || pubData[0] != 0x04)
	{
		// Raw: Too short or does not start with 0x04
		controlOctets = 0;
	}
	else if (pubData[1] < 0x80)
	{
		// Raw: Length octet does not match remaining data length
		if (pubData[1] != (len - controlOctets)) controlOctets = 0;
	}
	else
	{
		size_t lengthOctets = pubData[1] & 0x7F;
		controlOctets += lengthOctets;

		if (controlOctets >= len)
		{
			// Raw: Too short
			controlOctets = 0;
		}
		else
		{
			ByteString length(&pubData[2], lengthOctets);

			if (length.long_val() != (len - controlOctets))
			{
				// Raw: Length octets does not match remaining data length
				controlOctets = 0;
			}
		}
	}

	// DER format
	if (controlOctets == 0)
		pubData = DERUTIL::raw2Octet(pubData);

	ecPubKey.setQ(pubData);

	return CKR_OK;
}

CK_RV KeyHandler::getEDDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, ByteString pubData)
{
	auto& edPubKey = static_cast<EDPublicKey&>(publicKey);
	auto& edPrivKey = static_cast<EDPrivateKey&>(privateKey);

	// Copy Domain Parameters from Private Key
	edPubKey.setEC(edPrivKey.getEC());

	size_t len = pubData.size();
	size_t controlOctets = 2;
	if (len == 32 || len == 65 || len == 97 || len == 133)
	{
		// Raw: Length matches the public key size of:
		// EDDSA: X25519
		// ECDSA: P-256, P-384, or P-521
		controlOctets = 0;
	}
	else if (len < controlOctets || pubData[0] != 0x04)
	{
		// Raw: Too short or does not start with 0x04
		controlOctets = 0;
	}
	else if (pubData[1] < 0x80)
	{
		// Raw: Length octet does not match remaining data length
		if (pubData[1] != (len - controlOctets)) controlOctets = 0;
	}
	else
	{
		size_t lengthOctets = pubData[1] & 0x7F;
		controlOctets += lengthOctets;

		if (controlOctets >= len)
		{
			// Raw: Too short
			controlOctets = 0;
		}
		else
		{
			ByteString length(&pubData[2], lengthOctets);

			if (length.long_val() != (len - controlOctets))
			{
				// Raw: Length octets does not match remaining data length
				controlOctets = 0;
			}
		}
	}

	// DER format
	if (controlOctets == 0)
		pubData = DERUTIL::raw2Octet(pubData);

	edPubKey.setA(pubData);

	return CKR_OK;
}
