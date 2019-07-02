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

#include "config.h"
#include "log.h"
#include "ObjectStore.h"
#include "Token.h"
#include "OSAttribute.h"
#include "ByteString.h"
#include "SecureDataManager.h"
#include <cstdio>
#include <iostream>
#include <cassert>

#ifndef _WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif

// Constructor, hiddden
SoftToken::SoftToken()
	: valid(false), library(nullptr), token(nullptr), sdm(nullptr)
	, symAlgo(nullptr, &KeyHandler::recycleSymAlgo)
	, hashAlgo(nullptr, &KeyHandler::recycleHashAlgo)
	, hashType(HashAlgo::Type::Unknown)
	, macAlgo(nullptr, &KeyHandler::recycleMacAlgo)
	, asymAlgo(nullptr, &KeyHandler::recycleAsymAlgo)
	, asymMechanism(AsymMech::Type::Unknown)
	, privateKey(nullptr)
{
	tokenMutex = MutexFactory::i()->getMutex();
}

// Constructor, for a fully fledged token
SoftToken::SoftToken(ObjectStoreToken* inToken, tokenlib_type inLibrary)
	: library(inLibrary), token(inToken)
	, symAlgo(nullptr, &KeyHandler::recycleSymAlgo)
	, hashAlgo(nullptr, &KeyHandler::recycleHashAlgo)
	, hashType(HashAlgo::Type::Unknown)
	, macAlgo(nullptr, &KeyHandler::recycleMacAlgo)
	, asymAlgo(nullptr, &KeyHandler::recycleAsymAlgo)
	, asymMechanism(AsymMech::Type::Unknown)
	, privateKey(nullptr)
{
	assert(token != NULL);

	tokenMutex = MutexFactory::i()->getMutex();

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	sdm = new SecureDataManager(soPINBlob, userPINBlob);

	// clear PIN
	soPINBlob.wipe(0);
	userPINBlob.wipe(0);
}

// Constructor for an empty token without any storage yet connected (uninitialized)
SoftToken::SoftToken(tokenlib_type inLibrary)
	: valid(false), library(inLibrary), token(nullptr), sdm(nullptr)
	, symAlgo(nullptr, &KeyHandler::recycleSymAlgo)
	, hashAlgo(nullptr, &KeyHandler::recycleHashAlgo)
	, hashType(HashAlgo::Type::Unknown)
	, macAlgo(nullptr, &KeyHandler::recycleMacAlgo)
	, asymAlgo(nullptr, &KeyHandler::recycleAsymAlgo)
	, asymMechanism(AsymMech::Type::Unknown)
	, privateKey(nullptr)
{
	tokenMutex = MutexFactory::i()->getMutex();
}

// Destructor
SoftToken::~SoftToken()
{
	if (sdm != NULL) delete sdm;

	MutexFactory::i()->recycleMutex(tokenMutex);
}

// Check if the token is still valid
bool SoftToken::isValid() const
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	return (valid && token->isValid());
}

// Check if the token is initialized
bool SoftToken::isInitialized() const
{
	if (token == NULL) return false;

	return true;
}

// Check if SO is logged in
bool SoftToken::isSOLoggedIn() const
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->isSOLoggedIn();
}

// Check if user is logged in
bool SoftToken::isUserLoggedIn() const
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->isUserLoggedIn();
}

// Login SO
CK_RV SoftToken::loginSO(const ByteString& pin)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	// User cannot be logged in
	if (sdm->isUserLoggedIn()) return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	// SO cannot be logged in
	if (sdm->isSOLoggedIn()) return CKR_USER_ALREADY_LOGGED_IN;

	// Get token flags
	if (!token->getTokenFlags(flags))
	{
		ERROR_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	// Login
	if (!sdm->loginSO(pin))
	{
		ERROR_MSG("Logging in SO failed");
		flags |= CKF_SO_PIN_COUNT_LOW;
		token->setTokenFlags(flags);
		return CKR_PIN_INCORRECT;
	}

	DEBUG_MSG("SO login succeeded");
	flags &= ~CKF_SO_PIN_COUNT_LOW;
	token->setTokenFlags(flags);
	return CKR_OK;
}

// Login user
CK_RV SoftToken::loginUser(const ByteString& pin)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	// SO cannot be logged in
	if (sdm->isSOLoggedIn()) return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	// User cannot be logged in
	if (sdm->isUserLoggedIn()) return CKR_USER_ALREADY_LOGGED_IN;

	// The user PIN has to be initialized;
	if (sdm->getUserPINBlob().size() == 0) return CKR_USER_PIN_NOT_INITIALIZED;

	// Get token flags
	if (!token->getTokenFlags(flags))
	{
		ERROR_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	// Login
	if (!sdm->loginUser(pin))
	{
		ERROR_MSG("Logging in User failed");
		flags |= CKF_USER_PIN_COUNT_LOW;
		if (!token->setTokenFlags(flags))
			ERROR_MSG("Failed to set user Token flags during login");

		return CKR_PIN_INCORRECT;
	}

	DEBUG_MSG("User login succeeded");
	flags &= ~CKF_USER_PIN_COUNT_LOW;

	DEBUG_MSG("User Setting token flags");
	if (!token->setTokenFlags(flags))
		ERROR_MSG("Failed to set user Token flags");

	return CKR_OK;
}

CK_RV SoftToken::reAuthenticate(const ByteString& pin)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	// Get token flags
	if (!token->getTokenFlags(flags))
	{
		ERROR_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	if (sdm->isSOLoggedIn())
	{
		// Login
		if (!sdm->reAuthenticateSO(pin))
		{
			flags |= CKF_SO_PIN_COUNT_LOW;
			if (!token->setTokenFlags(flags))
				ERROR_MSG("Failed to set SO Token flags during reauthenticate");

			return CKR_PIN_INCORRECT;
		}
		else
		{
			flags &= ~CKF_SO_PIN_COUNT_LOW;
			token->setTokenFlags(flags);
		}
	}
	else if (sdm->isUserLoggedIn())
	{
		// Login
		if (!sdm->reAuthenticateUser(pin))
		{
			flags |= CKF_USER_PIN_COUNT_LOW;
			if (!token->setTokenFlags(flags))
				ERROR_MSG("Failed to set user Token flags during reauthenticate");

			return CKR_PIN_INCORRECT;
		}
		else
		{
			flags &= ~CKF_USER_PIN_COUNT_LOW;
			token->setTokenFlags(flags);
		}
	}
	else
	{
		ERROR_MSG("Failed to reauthenticate");
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_OK;
}

// Logout any user on this token;
void SoftToken::logout()
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return;

	DEBUG_MSG("Logging out user");

	sdm->logout();
}

// Change SO PIN
CK_RV SoftToken::setSOPIN(const ByteString& oldPIN, const ByteString& newPIN)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	// Get token flags
	if (!token->getTokenFlags(flags))
	{
		ERROR_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	// Verify oldPIN
	SecureDataManager* verifier = new SecureDataManager(sdm->getSOPINBlob(), sdm->getUserPINBlob());
	bool result = verifier->loginSO(oldPIN);
	delete verifier;
	if (result == false)
	{
		flags |= CKF_SO_PIN_COUNT_LOW;
		token->setTokenFlags(flags);
		return CKR_PIN_INCORRECT;
	}

	if (sdm->setSOPIN(newPIN) == false) return CKR_GENERAL_ERROR;

	// Save PIN to token file
	if (token->setSOPIN(sdm->getSOPINBlob()) == false) return CKR_GENERAL_ERROR;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);
	
	// clear PIN
	soPINBlob.wipe(0);
	userPINBlob.wipe(0);

	flags &= ~CKF_SO_PIN_COUNT_LOW;
	if (!token->setTokenFlags(flags))
		ERROR_MSG("Failed to set Token flags during SO Login");

	return CKR_OK;
}

// Change the user PIN
CK_RV SoftToken::setUserPIN(const ByteString& oldPIN, const ByteString& newPIN)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	// Check if user should stay logged in
	bool stayLoggedIn = sdm->isUserLoggedIn();

	// Get token flags
	if (!token->getTokenFlags(flags))
	{
		ERROR_MSG("Could not get the token flags");
		return CKR_GENERAL_ERROR;
	}

	// Verify oldPIN
	SecureDataManager* newSdm = new SecureDataManager(sdm->getSOPINBlob(), sdm->getUserPINBlob());
	if (newSdm->loginUser(oldPIN) == false)
	{
		ERROR_MSG("Failed to set user PIN. PIN was incorrect");
		flags |= CKF_USER_PIN_COUNT_LOW;
		if (!token->setTokenFlags(flags))
			ERROR_MSG("Failed to set user Token flags during set of User PIN");

		delete newSdm;
		return CKR_PIN_INCORRECT;
	}

	// Set the new user PIN
	if (newSdm->setUserPIN(newPIN) == false)
	{
		ERROR_MSG("Failed to set user PIN. User not logged in, or PIN invalid");

		delete newSdm;
		return CKR_GENERAL_ERROR;
	}

	// Save PIN to token file
	if (token->setUserPIN(newSdm->getUserPINBlob()) == false)
	{
		ERROR_MSG("Failed to set user PIN to file. ");

		delete newSdm;
		return CKR_GENERAL_ERROR;
	}

	// Restore previous login state
	if (!stayLoggedIn) newSdm->logout();

	// Switch sdm
	delete sdm;
	sdm = newSdm;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);
	ERROR_MSG("Error setting user PIN in SGX HW Token. SO and User PIN invalid");

	// clear PIN
	soPINBlob.wipe(0);
	userPINBlob.wipe(0);

	flags &= ~CKF_USER_PIN_COUNT_LOW;
	if (!token->setTokenFlags(flags))
		ERROR_MSG("Failed to set user Token flags in set user PIN");

	return CKR_OK;
}

// Init the user PIN
CK_RV SoftToken::initUserPIN(const ByteString& pin)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (!isInitialized()) return CKR_GENERAL_ERROR;

	if (sdm->setUserPIN(pin) == false) return CKR_GENERAL_ERROR;

	// Save PIN to token file
	if (token->setUserPIN(sdm->getUserPINBlob()) == false) return CKR_GENERAL_ERROR;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);
	ERROR_MSG("Error initializing user PIN in SGX HW Token. SO and User PIN invalid");
	
	// clear PIN
	soPINBlob.wipe(0);
	userPINBlob.wipe(0);

	return CKR_OK;
}

// Create a new token
CK_RV SoftToken::createToken(ObjectStore* objectStore, const ByteString& soPIN, CK_UTF8CHAR_PTR label)
{
	CK_ULONG flags;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (objectStore == NULL) return CKR_GENERAL_ERROR;

	if (label == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Convert the label
	ByteString labelByteStr((const unsigned char*) label, 32);

	if (token != NULL)
	{
		// Get token flags
		if (!token->getTokenFlags(flags))
		{
			ERROR_MSG("Could not get the SGX HW Token flags");
			return CKR_GENERAL_ERROR;
		}

		// Verify SO PIN
		if (sdm->getSOPINBlob().size() > 0 && !sdm->loginSO(soPIN))
		{
			flags |= CKF_SO_PIN_COUNT_LOW;
			if (!token->setTokenFlags(flags))
				ERROR_MSG("Failed to set user Token flags during get SO PIN or SO Login");

			ERROR_MSG("SGX HW Token incorrect SO PIN");
			return CKR_PIN_INCORRECT;
		}
		
		flags &= ~CKF_SO_PIN_COUNT_LOW;
		token->setTokenFlags(flags);

		DEBUG_MSG("Resetting SGX HW Token");
		// Reset the token
		if (!token->resetToken(labelByteStr))
		{
			ERROR_MSG("Could not reset the SGX HW Token");
			return CKR_DEVICE_ERROR;
		}
	}
	else
	{
		DEBUG_MSG("Creating SGX HW Token");
		// Generate the SO PIN blob
		SecureDataManager soPINBlobGen;

		if (!soPINBlobGen.setSOPIN(soPIN))
		{
			return CKR_GENERAL_ERROR;
		}

		// Create the token
		ObjectStoreToken* newToken = objectStore->newToken(labelByteStr);

		if (newToken == NULL)
		{
			ERROR_MSG("Could not create the SGX HW Token");
			return CKR_DEVICE_ERROR;
		}

		// Set the SO PIN on the token
		if (!newToken->setSOPIN(soPINBlobGen.getSOPINBlob()))
		{
			ERROR_MSG("Failed to set SO PIN on new SGX HW Token");

			if (!objectStore->destroyToken(newToken))
				ERROR_MSG("Failed to destroy incomplete SGX HW Token");

			return CKR_DEVICE_ERROR;
		}

		token = newToken;
	}

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);
	ERROR_MSG("Error initializing user PIN in SGX HW Token. SO and User PIN invalid");

	if (sdm != NULL) delete sdm;
	sdm = new SecureDataManager(soPINBlob, userPINBlob);

	// clear PIN
	soPINBlob.wipe(0);
	userPINBlob.wipe(0);

	return CKR_OK;
}

// Retrieve token information for the token
CK_RV SoftToken::getTokenInfo(CK_TOKEN_INFO_PTR info)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	DEBUG_MSG("Retrieving SGX HW Token information");

	ByteString label, serial;

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	memset(info->label, ' ', 32);
	memset(info->serialNumber, ' ', 16);

	// Token specific information
	if (token)
	{
		if (!token->getTokenFlags(info->flags))
		{
			ERROR_MSG("Could not get the SGX HW Token flags");
			return CKR_GENERAL_ERROR;
		}

		if (token->getTokenLabel(label))
		{
			strncpy((char*) info->label, (char*) label.byte_str(), label.size());
		}

		if (token->getTokenSerial(serial))
		{
			strncpy((char*) info->serialNumber, (char*) serial.byte_str(), serial.size());
		}
	}
	else
	{
		info->flags =	CKF_RNG |
				CKF_LOGIN_REQUIRED |
				CKF_RESTORE_KEY_NOT_NEEDED |
				CKF_SO_PIN_LOCKED |
				CKF_SO_PIN_TO_BE_CHANGED;
	}

	// Information shared by all tokens
	char mfgID[33];
	char model[17];

	snprintf(mfgID, 33, "SoftHSM project");
	snprintf(model, 17, "SoftHSM v2");

	memset(info->manufacturerID, ' ', 32);
	memset(info->model, ' ', 16);
	memcpy(info->manufacturerID, mfgID, strlen(mfgID));
	memcpy(info->model, model, strlen(model));

	info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxPinLen = MAX_PIN_LEN;
	info->ulMinPinLen = MIN_PIN_LEN;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->hardwareVersion.major = VERSION_MAJOR;
	info->hardwareVersion.minor = VERSION_MINOR;
	info->firmwareVersion.major = VERSION_MAJOR;
	info->firmwareVersion.minor = VERSION_MINOR;

	// Current time
	time_t rawtime;
	time(&rawtime);
	char dateTime[17];
	tm *time = gmtime(&rawtime);
	if (time)
	{
		strftime(dateTime, 17, "%Y%m%d%H%M%S00", time);
		memcpy(info->utcTime, dateTime, 16);
	}

	return CKR_OK;
}

// Create an object
OSObject* SoftToken::createObject()
{
	return token->createObject();
}

void SoftToken::getObjects(std::set<OSObject *> &objects)
{
	token->getObjects(objects);
}

SymmetricAlgorithm* SoftToken::getSymAlgo() const
{
	return symAlgo.get();
}

void SoftToken::setSymAlgo(SymmetricAlgorithm* algo)
{
	symAlgo.reset(algo);
}

void SoftToken::resetSymAlgo()
{
	symAlgo.reset();
}

void SoftToken::setHashAlgo(HashAlgorithm* algo, const HashAlgo::Type& type)
{
	hashAlgo.reset(algo);
	hashType = type;
}

HashAlgorithm* SoftToken::getHashAlgo() const
{
	return hashAlgo.get();
}

HashAlgo::Type SoftToken::getHashType() const
{
	return hashType;
}

void SoftToken::resetHashAlgo()
{
	hashAlgo.reset();
	hashType = HashAlgo::Type::Unknown;
}

void SoftToken::setMacSymAlgo(MacAlgorithm* algo, const SymmetricKey& symKey)
{
	macAlgo.reset(algo);
	symmetricKey = symKey;
}

MacAlgorithm* SoftToken::getMacAlgo() const
{
	return macAlgo.get();
}

SymmetricKey* SoftToken::getSymmetricKey()
{
	return &symmetricKey;
}

void SoftToken::resetMacAlgo()
{
	macAlgo.reset();
}

void SoftToken::setAsymAlgo(AsymmetricAlgorithm* algo, const AsymMech::Type& type)
{
	asymAlgo.reset(algo);
	asymMechanism = type;
}

AsymmetricAlgorithm* SoftToken::getAsymAlgo() const
{
	return asymAlgo.get();
}

AsymMech::Type SoftToken::getAsymMech() const
{
	return asymMechanism;
}

void SoftToken::resetAsymAlgo()
{
	asymAlgo.reset();
	privateKey.reset();
	publicKey.reset();
	asymMechanism = AsymMech::Type::Unknown;
}

void SoftToken::setPrivateKey(PrivateKey* privKey)
{
	privateKey.reset(privKey);
}

PrivateKey* SoftToken::getPrivateKey() const
{
	return privateKey.get();
}

void SoftToken::setPublicKey(PublicKey* pubKey)
{
	publicKey.reset(pubKey);
}

PublicKey* SoftToken::getPublicKey() const
{
	return publicKey.get();
}

bool SoftToken::decrypt(const ByteString &encrypted, ByteString &plaintext)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->decrypt(encrypted,plaintext);
}

bool SoftToken::encrypt(const ByteString &plaintext, ByteString &encrypted)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->encrypt(plaintext,encrypted);
}
