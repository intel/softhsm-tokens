#ifndef _SOFTHSM_V2_SOFTTOKEN_CRYPTOHANDLER_H
#define _SOFTHSM_V2_SOFTTOKEN_CRYPTOHANDLER_H


#include <pkcs11.h>
#include <vector>

// forward declarations
struct token_mechanism_struct;
class SoftToken;
class OSObject;

class CryptoHandler
{
public:
	static CK_RV getMechanismList(std::vector<token_mechanism_struct>& mechanisms);

	static CK_RV unwrapKey(SoftToken& token, OSObject& unwrappingKey, OSObject*& newKey,
	                       CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, unsigned long attribute_count,
	                       unsigned char* wrapped_key, unsigned long wrapped_key_len);

	static CK_RV generateKey(SoftToken& token, OSObject*& key, CK_MECHANISM_PTR mechanism,
							CK_ATTRIBUTE_PTR templ, unsigned long count);

	static CK_RV generateKeyPair(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
			CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
			CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count);
};


#endif //_SOFTHSM_V2_SOFTTOKEN_CRYPTOHANDLER_H
