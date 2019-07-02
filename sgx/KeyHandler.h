#ifndef _SOFTHSM_V2_SOFTTOKEN_KEYHANDLER_H
#define _SOFTHSM_V2_SOFTTOKEN_KEYHANDLER_H

#include <pkcs11.h>

#include <CryptoFactory.h>

#include <memory>

// forward declarations
class SoftToken;
class OSObject;

class ByteString;

class SymmetricKey;
class PublicKey;
class PrivateKey;

class AsymmetricAlgorithm;
class SymmetricAlgorithm;
class HashAlgorithm;
class MacAlgorithm;


class KeyHandler
{
public:
	static inline void recycleAsymAlgo(AsymmetricAlgorithm* algo)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(algo);
	}

	static inline void recycleSymAlgo(SymmetricAlgorithm* algo)
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(algo);
	}

	static inline void recycleHashAlgo(HashAlgorithm* algo)
	{
		CryptoFactory::i()->recycleHashAlgorithm(algo);
	}

	static inline void recycleMacAlgo(MacAlgorithm* algo)
	{
		CryptoFactory::i()->recycleMacAlgorithm(algo);
	}

// for objects created by algorithms they should probably own those instances themselves
// work for the future
	using AsymAlgoPtr = std::unique_ptr<AsymmetricAlgorithm, decltype(&recycleAsymAlgo)>;
	using SymAlgoPtr = std::unique_ptr<SymmetricAlgorithm, decltype(&recycleSymAlgo)>;
	using HashAlgoPtr = std::unique_ptr<HashAlgorithm, decltype(&recycleHashAlgo)>;
	using MacAlgoPtr = std::unique_ptr<MacAlgorithm, decltype(&recycleMacAlgo)>;


	// generate
	static CK_RV generateDSAParameters(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateDHParameters(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateDES(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateDES2(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateDES3(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateAES(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);
	static CK_RV generateGeneric(SoftToken& token, CK_ATTRIBUTE_PTR templ, CK_ULONG count, OSObject*& key, CK_BBOOL isPrivate);

	// generate keypairs
	static CK_RV generateRSA(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                         CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                         CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                         CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static CK_RV generateDSA(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                         CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                         CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                         CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static CK_RV generateEC(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                         CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                         CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                         CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static CK_RV generateDH(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                        CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                        CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                        CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static CK_RV generateGOST(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                        CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                        CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                        CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static CK_RV generateED(SoftToken& token, OSObject*& publicKey, OSObject*& privateKey,
	                          CK_ATTRIBUTE_PTR public_templ, unsigned long public_templ_count,
	                          CK_ATTRIBUTE_PTR private_templ, unsigned long private_templ_count,
	                          CK_BBOOL isPublicKeyPrivate, CK_BBOOL isPrivateKeyPrivate);

	static bool getPlainCKV(SymmetricKey* key, CK_KEY_TYPE keyType, size_t& byteLen, ByteString& plainKCV);

	static CK_RV getSymmetricKey(SoftToken& token, SymmetricKey& skey, OSObject& key);

	static CK_RV getRSAPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key);
	static CK_RV getRSAPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);
	static bool  setRSAPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber);

	static CK_RV getDSAPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key);
	static CK_RV getDSAPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);
	static bool  setDSAPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber);

	static CK_RV getDHPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);
	static bool  setDHPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber);

	static CK_RV getECPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key);
	static CK_RV getECPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);
	static bool  setECPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber);

	static CK_RV getEDPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key);
	static CK_RV getEDPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);

	static CK_RV getGOSTPublicKey(SoftToken& token, PublicKey& publicKey, OSObject& key);
	static CK_RV getGOSTPrivateKey(SoftToken& token, PrivateKey& privateKey, OSObject& key);
	static bool  setGOSTPrivateKey(SoftToken& token, OSObject& key, const ByteString& ber);

	static CK_RV getDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, const ByteString& pubData);
	static CK_RV getECDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, ByteString pubData);
	static CK_RV getEDDHPublicKey(PublicKey& publicKey, PrivateKey& privateKey, ByteString pubData);
};


#endif //_SOFTHSM_V2_SOFTTOKEN_KEYHANDLER_H
