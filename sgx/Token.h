/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SoftToken.h

 Software implementation of a token
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SOFTTOKEN_SOFTTOKEN_H
#define _SOFTHSM_V2_SOFTTOKEN_SOFTTOKEN_H

#include "config.h"
#include "ByteString.h"
#include "ObjectStore.h"
#include "ObjectStoreToken.h"
#include "SecureDataManager.h"
#include "cryptoki.h"

#include "KeyHandler.h"

#include <string>
#include <vector>

#include "interface.h"

class SoftToken
{
public:
	// Constructor
	SoftToken(ObjectStoreToken *inToken, tokenlib_type inLibrary);
	SoftToken(tokenlib_type inLibrary);

	SoftToken(const SoftToken&) = delete;
	SoftToken& operator=(const SoftToken&) = delete;
	// Destructor
	virtual ~SoftToken();

	// Create a new SoftToken
	CK_RV createToken(ObjectStore* objectStore, const ByteString& soPIN, CK_UTF8CHAR_PTR label);

	// Is the token valid?
	bool isValid() const;

	// Is the token initialized?
	bool isInitialized() const;

	// Is SO or user logged in?
	bool isSOLoggedIn() const;
	bool isUserLoggedIn() const;

	// Login
	CK_RV loginSO(const ByteString& pin);
	CK_RV loginUser(const ByteString& pin);

	// Re-authentication
	CK_RV reAuthenticate(const ByteString& pin);

	// Logout any user on this token;
	void logout();

	// Change PIN
	CK_RV setSOPIN(const ByteString& oldPIN, const ByteString& newPIN);
	CK_RV setUserPIN(const ByteString& oldPIN, const ByteString& newPIN);
	CK_RV initUserPIN(const ByteString& pin);

	// Retrieve token information for the token
	CK_RV getTokenInfo(CK_TOKEN_INFO_PTR info);

	// Create object
	OSObject *createObject();

	// Insert all token objects into the given set.
	void getObjects(std::set<OSObject *> &objects);

	// Takes ownership of this algorithm
	void setSymAlgo(SymmetricAlgorithm* algo);
	SymmetricAlgorithm* getSymAlgo() const;
	void resetSymAlgo();

	void setHashAlgo(HashAlgorithm* algo, const HashAlgo::Type& type);
	HashAlgorithm* getHashAlgo() const;
	HashAlgo::Type getHashType() const;
	void resetHashAlgo();

	void setMacSymAlgo(MacAlgorithm* algo, const SymmetricKey& symKey);
	MacAlgorithm* getMacAlgo() const;
	SymmetricKey* getSymmetricKey();
	void resetMacAlgo();

	void setAsymAlgo(AsymmetricAlgorithm* algo, const AsymMech::Type& type);
	AsymmetricAlgorithm* getAsymAlgo() const;
	AsymMech::Type getAsymMech() const;
	void resetAsymAlgo();

	void setPrivateKey(PrivateKey* privKey);
	PrivateKey* getPrivateKey() const;
	void setPublicKey(PublicKey* pubKey);
	PublicKey* getPublicKey() const;

	// Decrypt the supplied data
	bool decrypt(const ByteString& encrypted, ByteString& plaintext);

	// Encrypt the supplied data
	bool encrypt(const ByteString& plaintext, ByteString& encrypted);

        tokenlib_type library;

private:
	SoftToken();
	// Token validity
	bool valid;
        
	// A reference to the object store token
	ObjectStoreToken* token;

	// The secure data manager for this token
	SecureDataManager* sdm;

	Mutex* tokenMutex;

	KeyHandler::SymAlgoPtr symAlgo;
	KeyHandler::HashAlgoPtr hashAlgo;
	HashAlgo::Type hashType;
	KeyHandler::MacAlgoPtr macAlgo;
	SymmetricKey symmetricKey;
	KeyHandler::AsymAlgoPtr asymAlgo;
	AsymMech::Type asymMechanism;
	std::unique_ptr<PrivateKey> privateKey;
	std::unique_ptr<PublicKey> publicKey;
};

#endif // !_SOFTHSM_V2_TOKEN_H
