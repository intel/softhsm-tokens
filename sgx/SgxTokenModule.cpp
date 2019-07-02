#include "config.h"

#include <cassert>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <cassert>
#include "interface.h"
#include "Token.h"
#include "ObjectHandler.h"
#include "CryptoHandler.h"
#include "TokenExtension.h"
#include "ObjectStore.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "CryptoFactory.h"

// needed to load SGX Crypto API
#include "library.h"

// Constants
int cToolkitSlotID = 0;
unsigned char* cToolkitPIN = NULL_PTR;
unsigned long cToolkitPINlength = 0;
unsigned char* cToolkitLabel = NULL_PTR;

using MechanismArray = std::pair<token_mechanism_struct*, int>;
static std::vector<token_mechanism_struct> mMechanisms;
static int loaded = 0;

std::unordered_map<CK_SESSION_HANDLE, unsigned long> sessionHandleMap;
std::unordered_map<CK_SLOT_ID, std::unordered_set<CK_SESSION_HANDLE>> slotSessionMap;
std::unordered_map<CK_SESSION_HANDLE, CK_SLOT_ID> sessionSlotMap;

// internal CK_SESSION_HANDLE counter
unsigned long sessionCounter = 0;

/*
* SGX Token's Context structure 
*/
struct session_context
{
    unsigned long sessionID;
};

static MechanismArray getMechanisms()
{
    if (mMechanisms.empty())
        CryptoHandler::getMechanismList(mMechanisms); /*CK_RV rv = */

    // on older compilers data might be const only
    return std::make_pair(mMechanisms.data(), mMechanisms.size());
}

// Prototypes and members for loading SGX Provider
char* p11ProviderName = "/usr/local/lib/softhsm/libp11sgx.so";
void* p11ProviderHandle;
CK_FUNCTION_LIST_PTR p11;

CK_RV loadTokenModule()
{   
    if (p11 != NULL)
    {
        DEBUG_MSG("SGX Crypto API Toolkit already loaded");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    
    DEBUG_MSG("Loading SGX Crypto API Toolkit");

    // Load SGX P11 Provider & Enclave
	char* errMsg = NULL;

	CK_C_GetFunctionList pGetFunctionList = loadLibrary(p11ProviderName, &p11ProviderHandle, &errMsg);
	if (!pGetFunctionList)
	{
        ERROR_MSG("Failed to load the SGX Crypto API Toolkit %s", errMsg);
		return CKR_LIBRARY_LOAD_FAILED;
	}

	// Load the function list
	(*pGetFunctionList)(&p11);

	return (pGetFunctionList != nullptr) ? CKR_OK : CKR_LIBRARY_LOAD_FAILED;
}

CK_RV unloadTokenModule()
{
    CK_RV rv = CKR_GENERAL_ERROR;

    if (p11 == NULL || p11ProviderHandle == NULL)
    {
        DEBUG_MSG("SGX Crypto API Toolkit already unloaded");
        return CKR_OK;
    }

    DEBUG_MSG("Finalizing SGX Crypto API Toolkit");
    rv = p11->C_Finalize(NULL_PTR);

    DEBUG_MSG("Unloading SGX Crypto API Toolkit");
    unloadLibrary(p11ProviderHandle);
    
    p11ProviderHandle = NULL;
    p11 = NULL;

    return rv;
}

/* SoftHSM Session Handle - SGX Session Handle Mapping */
bool get_session_handle(CK_SESSION_HANDLE *softHSMHandle, CK_SESSION_HANDLE *sgxHandle)
{
    if (softHSMHandle == nullptr || sgxHandle == nullptr)
        return false;

    if (sessionHandleMap.find(*softHSMHandle) == sessionHandleMap.end())
    {
        DEBUG_MSG("Failed to find session handle in SGX HW Token %lu", softHSMHandle);
        return false;
    }
    
    *sgxHandle = sessionHandleMap[*softHSMHandle];

    return true;
}

CK_RV get_session_handle(tokencontext_type context, CK_SESSION_HANDLE *phSession, CK_SESSION_HANDLE *sgxHandle)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    do
    {
        if (context == nullptr)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        if (phSession == nullptr || sgxHandle == nullptr)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        session_context *iContext = static_cast<session_context*>(context->getsession(context));
        *phSession = iContext->sessionID;

        if (!get_session_handle(phSession, sgxHandle))
        {
            rv = CKR_SESSION_HANDLE_INVALID;
            break;
        }

        rv = CKR_OK;

    } while (false);

    return rv;
}

bool set_session_handle(CK_SESSION_HANDLE softHSMHandle, CK_SESSION_HANDLE sgxHandle)
{
    if (sessionHandleMap.find(softHSMHandle) != sessionHandleMap.end())
    {
        DEBUG_MSG("Failed to set session handle in SGX HW Token. Couldn't find session handle %lu", softHSMHandle);
        return false;
    }

    sessionHandleMap.insert({softHSMHandle, sgxHandle});

    return true;
}

bool remove_session_handle(CK_SESSION_HANDLE softHSMHandle)
{
    if (sessionHandleMap.find(softHSMHandle) == sessionHandleMap.end())
    {
        DEBUG_MSG("Failed to remove session handle in SGX HW Token. Couldn't find session handle %lu", softHSMHandle);
        return false;
    }

    DEBUG_MSG("Removing session handle %lu", softHSMHandle);

    sessionHandleMap.erase(softHSMHandle);

    return true;
}

/* Session - Slot Mapping */
bool get_session_slot(CK_SESSION_HANDLE phSession, CK_SLOT_ID *slotID)
{
    if (slotID == NULL)
        return false;

    if (sessionSlotMap.find(phSession) == sessionSlotMap.end())
        return false;

    *slotID = sessionSlotMap[phSession];

    return true;
}

bool set_session_slot(CK_SLOT_ID slotId, CK_SESSION_HANDLE phSession, CK_SESSION_HANDLE sgxSession)
{
    // add session handle to set for slot & map session to slot
    std::unordered_set<CK_SESSION_HANDLE> sessions;
    if (slotSessionMap.find(slotId) == slotSessionMap.end())
        slotSessionMap.insert({slotId, sessions});

    DEBUG_MSG("Setting slot %lu with session value SoftHSM(%lu), SGX(%lu)", slotId, phSession, sgxSession);

    slotSessionMap[slotId].insert(phSession);
    sessionSlotMap.insert({phSession, slotId});

    return true;
}

bool remove_session_slot(CK_SESSION_HANDLE phSession)
{
    // get slot ID from session so we can remove session from map
    if (sessionSlotMap.find(phSession) != sessionSlotMap.end())
    {
        DEBUG_MSG("Removing session slot in SGX HW Token %lu", phSession);

        // remove session from set of sessions associated with this slot
        CK_SLOT_ID slotId = sessionSlotMap[phSession];
        slotSessionMap[slotId].erase(phSession);
        sessionSlotMap.erase(phSession);
    }

    return true;
}

int32_t token_load(CK_C_INITIALIZE_ARGS* args, char* tokenspec, tokenlib_type tokenlib, tokenhandle_type* tokenhandle)
{
    if(tokenhandle == NULL) {
        loaded = 0;
        return CKR_OK;
    }

    DEBUG_MSG("Loading SGX HW Token");

    ObjectStore* objectstore = ObjectStore::getStorage(tokenlib);
    if (loaded < objectstore->getTokenCount())
    {
        ObjectStoreToken* ostoken = objectstore->getToken(loaded++);
        *tokenhandle = new SoftToken(ostoken, tokenlib);
    }

    token_mechanism_struct* mechanisms;
    int nmechanisms;
    std::tie(mechanisms, nmechanisms) = getMechanisms();

    // needs to be called
    tokenlib->setmechanisms(tokenlib, nmechanisms, mechanisms);

    // Load SGX libraries
    CK_RV rv = loadTokenModule();
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
        return CKR_OK;

    DEBUG_MSG("SGX Crypto API Toolkit loaded");
    DEBUG_MSG("Initializing SGX Crypto API Toolkit");
    rv = p11->C_Initialize(NULL_PTR);
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
        rv = CKR_OK;

    if (rv != CKR_OK)
    {
        DEBUG_MSG("Failed to initialize SGX Crypto API Toolkit: %lu", rv);
        return rv;
    }

    DEBUG_MSG("Initializing Token in SGX Crypto API Toolkit");
    rv = p11->C_InitToken(cToolkitSlotID, cToolkitPIN, cToolkitPINlength, cToolkitLabel);
    if (rv != CKR_OK)
    {
        ERROR_MSG("Failed to init token in SGX Crypto API Toolkit %lu", rv);
        if (rv == CKR_DEVICE_ERROR)
            ERROR_MSG("Failed to load SGX Enclave");
    }

    return rv;
}

int32_t token_createtoken(tokenlib_type tokenlib, tokenhandle_type* tokenhandle)
{
    DEBUG_MSG("SGX HW Token creating token");
    if (tokenlib == NULL || tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    *tokenhandle = new SoftToken(tokenlib);
    token_mechanism_struct* mechanisms;
    int nmechanisms;
    std::tie(mechanisms, nmechanisms) = getMechanisms();
    tokenlib->setmechanisms(tokenlib, nmechanisms, mechanisms);
    return CKR_OK;
}

int32_t token_close(tokenhandle_type tokenhandle)
{
    DEBUG_MSG("Closing SGX HW Token");
    if (p11 == NULL_PTR)
    {
        DEBUG_MSG("SGX HW Token already closed");
        return CKR_OK;
    }

    DEBUG_MSG("Closing all SGX Crypto API Toolkit sessions");
    CK_RV rv = p11->C_CloseAllSessions(cToolkitSlotID);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to close sessions in SGX Crypto API Toolkit %lu\n", rv);

    sessionSlotMap.clear();
    slotSessionMap.clear();
    sessionHandleMap.clear();

    rv = unloadTokenModule();
    if (rv != CKR_OK)
        ERROR_MSG("Failed to unload SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_validate(tokenhandle_type tokenhandle)
{
    DEBUG_MSG("Validating SGX HW Token");
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if(!token->isInitialized())
        return CKR_TOKEN_NOT_PRESENT;
    
    return CKR_OK;
}

int32_t token_getinfo(tokenhandle_type tokenhandle, CK_TOKEN_INFO* info)
{
    DEBUG_MSG("Getting info from SGX HW Token");
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    SoftToken* token = (SoftToken*)tokenhandle;
    CK_RV rv = token->getTokenInfo(info);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to get SGX HW Token info %lu", rv);

    return rv;
}

int32_t token_cleartoken(tokenhandle_type tokenhandle, unsigned char *pin, unsigned long pin_len, unsigned char *label)
{
    DEBUG_MSG("Clearing SGX HW Token ");
    if (tokenhandle == nullptr || pin == nullptr || label == nullptr || pin_len == 0)
        return CKR_ARGUMENTS_BAD;
    
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);

    CK_RV rv = token->createToken(ObjectStore::getStorage(token->library), {pin, pin_len}, label);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to create token in SGX HW Token");
    
    return rv;
}

int32_t token_adduser(tokenhandle_type tokenhandle, tokencontext_type context, 
        unsigned char *pin, unsigned long pin_len)
{
    DEBUG_MSG("Adding user to SGX HW Token");
    if (tokenhandle == nullptr || pin == nullptr || pin_len == 0)
        return CKR_ARGUMENTS_BAD;
    
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    CK_RV rv = token->initUserPIN({ pin, pin_len });
    if (rv != CKR_OK)
        ERROR_MSG("Failed to unload SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_changeuser(tokenhandle_type tokenhandle, tokencontext_type context, CK_USER_TYPE userType, 
        unsigned char *old_pin, unsigned long old_len, 
        unsigned char *new_pin, unsigned long new_len)
{
    DEBUG_MSG("Channging user in SGX HW Token");
    if (tokenhandle == nullptr || old_pin == nullptr || new_pin == nullptr 
        || old_len == 0 || new_len == 0)
        return CKR_ARGUMENTS_BAD;
    
    CK_RV rv = CKR_USER_TYPE_INVALID;
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    if (userType == CKU_SO)
    {
        DEBUG_MSG("Setting SGX HW Token SO PIN");
        rv = token->setSOPIN( {old_pin, old_len}, {new_pin, new_len} );
    }
    else if (userType == CKU_USER)
    {
        DEBUG_MSG("Setting SGX HW Token User PIN");
        rv = token->setUserPIN( {old_pin, old_len}, {new_pin, new_len} );
    }

    if (rv != CKR_OK)
        ERROR_MSG("Failed to change user in SGX HW Token %lu", rv);

    return rv;
}

int32_t token_createsession(tokenhandle_type tokenhandle, tokencontext_type tokencontext)
{
    DEBUG_MSG("Creating session in SGX HW Token");
    if (tokenhandle == nullptr || tokencontext == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    CK_SESSION_HANDLE sgxSession;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_OpenSession");
    CK_RV rv = p11->C_OpenSession(cToolkitSlotID, NULL, NULL, NULL, &sgxSession);

    if (rv == CKR_OK)
    {
        CK_SESSION_HANDLE phSession = sessionCounter++;

        if (!set_session_handle(phSession, sgxSession))
            return CKR_GENERAL_ERROR;

        if (!set_session_slot(cToolkitSlotID, phSession, sgxSession))
            return CKR_GENERAL_ERROR;

        // set the context data for this session
        session_context *iContext = new session_context();
        iContext->sessionID = phSession;

        tokencontext->setsession(tokencontext, iContext);
    }
    else
        ERROR_MSG("Failed to open session with SGX Crypto API Toolkit: %lu", rv);

    return rv;
}

int32_t token_endsession(tokenhandle_type tokenhandle, tokencontext_type context)
{
    DEBUG_MSG("Ending session in SGX HW Token");
    
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_CloseSession");
    rv = p11->C_CloseSession(sgxHandle);

    if (rv == CKR_OK)
    {
        if (!remove_session_handle(phSession))
            return CKR_GENERAL_ERROR;

        if (!remove_session_slot(phSession))
            return CKR_GENERAL_ERROR;
    }
    else
        ERROR_MSG("Failed to close session in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_authorize(tokenhandle_type tokenhandle, tokencontext_type context, CK_USER_TYPE usertype, unsigned char* pin, unsigned long pin_len)
{
    DEBUG_MSG("Authorizing user in SGX HW Token");
    if (tokenhandle == nullptr || pin == nullptr || pin_len == 0)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_USER_TYPE_INVALID;
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    if (usertype == CKU_USER)
    {
        rv = token->loginUser( {pin, pin_len} );
        if (rv == CKR_OK)
            DEBUG_MSG("SGX HW Token user logged in successfully");
    }
    else if (usertype == CKU_SO)
    {
        rv = token->loginSO( {pin, pin_len} );
        if (rv == CKR_OK)
            DEBUG_MSG("SGX HW Token SO logged in successfully");
    }

    if (rv != CKR_OK)
        ERROR_MSG("Failed to authorize user SGX HW Token %lu", rv);

    return rv;
}

int32_t token_revokeauthorization(tokenhandle_type tokenhandle, tokencontext_type context)
{
    DEBUG_MSG("Revoking SGX HW Token authorization");
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    token->logout();

    return CKR_OK;
}

int32_t token_createobject(tokenhandle_type tokenhandle, tokencontext_type context, CK_ATTRIBUTE *templ, unsigned long count)
{
    DEBUG_MSG("Creating object in SGX HW Token");
    if (tokenhandle == nullptr || context == nullptr)
        return CKR_ARGUMENTS_BAD;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    OSObject* newObj = nullptr;
    CK_RV rv =  ObjectHandler::createObject(*token, newObj, templ, count);
    if (newObj && rv == CKR_OK) 
         context->producedobjectptr(context, newObj, keytype_type::PUBLIC);
    
    if (rv != CKR_OK || newObj == NULL_PTR)
        ERROR_MSG("Failed to create object in SGX HW Token %lu", rv);

    return rv;
}

int32_t token_copyobject(tokenhandle_type tokenhandle, tokencontext_type context, CK_ATTRIBUTE* templ, unsigned long count)
{
    DEBUG_MSG("Copying object in SGX HW Token");
    if (tokenhandle == nullptr || context == nullptr)
        return CKR_ARGUMENTS_BAD;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;
    
    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    OSObject* newObj = nullptr;
    CK_RV rv = ObjectHandler::copyObject(*token, *osObj, newObj, templ, count);
    if (newObj && rv == CKR_OK)
	    context->producedobjectptr(context, newObj, keytype_type::PUBLIC);

    if (rv != CKR_OK || newObj == NULL_PTR)
        ERROR_MSG("Failed to copy object in SGX HW Token %lu", rv);
    
    return rv;
}

int32_t token_destroyobject(tokenhandle_type tokenhandle, tokencontext_type context)
{
    DEBUG_MSG("Destroying object in SGX HW Token");
    if (context == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));

    OSAttribute inEnclave = osObj->getAttribute(CKA_IN_ENCLAVE);
    if (inEnclave.getBooleanValue())
    {
        OSAttribute sessionID = osObj->getAttribute(CKA_ID);
        OSAttribute handleID = osObj->getAttribute(CKA_VALUE);
        rv = p11->C_DestroyObject(sessionID.getUnsignedLongValue(), handleID.getUnsignedLongValue());
        if (rv != CKR_OK)
            ERROR_MSG("Failed to destroy object in SGX Crypto API Toolkit %lu", rv);
    }

    rv = ObjectHandler::destroyObject(osObj);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to destroy object in SGX HW Token %lu", rv);

    return rv;
}

// not fully implemented in softhsm
int32_t token_getobjectsize(tokenhandle_type tokenhandle, tokencontext_type context, unsigned long* size)
{
    if (context == nullptr)
        return CKR_ARGUMENTS_BAD;

    //OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    *size = CK_UNAVAILABLE_INFORMATION;
    return CKR_OK;
}

int32_t token_getattributevalue(tokenhandle_type tokenhandle, tokencontext_type context, CK_ATTRIBUTE_PTR templ, unsigned long count)
{
    if (tokenhandle == nullptr || context == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    CK_RV rv =  ObjectHandler::getAttributeValue(*token, *osObj, templ, count);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to get attribute value in SGX HW Token %lu", rv);

    return rv;
}

int32_t token_setattributevalue(tokenhandle_type tokenhandle, tokencontext_type context, CK_ATTRIBUTE_PTR templ, unsigned long count)
{
    if (tokenhandle == nullptr || context == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    CK_RV rv;
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    rv =  ObjectHandler::setAttributeValue(*token, *osObj, templ, count);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to set attribute value in SGX HW Token %lu", rv);

    return rv;
}

int32_t token_searchobjectsstart(tokenhandle_type tokenhandle, tokencontext_type context)
{
    if (tokenhandle == nullptr || context == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    DEBUG_MSG("Initializing object search in SGX HW Token");

    CK_RV rv;
    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;
    
    CK_ATTRIBUTE_PTR templ = nullptr;
    unsigned long count = 0;
    unsigned long maxleft = 0; // ignored
    void* data; // ignored
    context->getsearchparameters(context, &templ, &count, &maxleft, data);

    // might need to check session here too
    std::set<OSObject*> matchingObjects;
    rv = ObjectHandler::findObjects(*token, templ, count, matchingObjects);
    if (rv == CKR_OK && !matchingObjects.empty()) {
        size_t i = 0;
        std::vector<void*> result;
        result.resize(matchingObjects.size());
        for (const auto obj : matchingObjects) {
            result[i++] = obj;
        }
        context->setsearchresult(context, result.data(), result.size());
    }

    if (rv != CKR_OK || matchingObjects.empty())
        ERROR_MSG("Failed to find objects SGX HW Token %lu", rv);

    return rv;
}

int32_t token_searchobjectsmore(tokenhandle_type tokenhandle, tokencontext_type context)
{
    DEBUG_MSG("SGX HW Token doesn't support 'searchobjectsmore'");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

int32_t token_searchobjectsstop(tokenhandle_type, tokencontext_type)
{   
    DEBUG_MSG("SGX HW Token doesn't support 'searchobjectsstop'");

    return CKR_FUNCTION_NOT_SUPPORTED;
}

int32_t token_encryptstart(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    if (context == nullptr)
        return CKR_ARGUMENTS_BAD;

    DEBUG_MSG("Initializing encryption in SGX HW Token");

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    OSAttribute nOsa = osObj->getAttribute(CKA_VALUE);
    unsigned long val = nOsa.getUnsignedLongValue();

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_EncryptInit");
    rv = p11->C_EncryptInit(sgxHandle, mechanism, val);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to initialize encrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_encrypt(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
    unsigned char *data, unsigned long data_len, 
    unsigned char *encrypted_data, unsigned long *encrypted_data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_Encrypt");
    rv = p11->C_Encrypt(sgxHandle, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to encrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_decryptstart(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));
    OSAttribute nOsa = osObj->getAttribute(CKA_VALUE);
    CK_OBJECT_HANDLE keyHandle = nOsa.getUnsignedLongValue();

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DecryptInit");
    rv = p11->C_DecryptInit(sgxHandle, mechanism, keyHandle);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to initialize decrypt SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_decrypt(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char *encrypted_data, unsigned long encrypted_data_len, 
    unsigned char *data, unsigned long *data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;  

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_Decrypt");
    rv = p11->C_Decrypt(sgxHandle, encrypted_data, encrypted_data_len, data, data_len); 
    if (rv != CKR_OK)
        ERROR_MSG("Failed to decrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_digeststart(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DigesttInit");
    rv = p11->C_DigestInit(sgxHandle, mechanism);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to initialize digest SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_digest(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char* data, unsigned long data_len, 
    unsigned char* digest, unsigned long* digest_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;
    
    DEBUG_MSG("Calling  SGX Crypto API Toolkit C_Digest");
    rv = p11->C_Digest(sgxHandle, data, data_len, digest, digest_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to perform digest in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_signstart(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;
    
    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));

    OSAttribute sha = osObj->getAttribute(CKA_VALUE);
    CK_OBJECT_HANDLE signHandle = sha.getUnsignedLongValue();
    
    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DecryptInit");
    rv = p11->C_SignInit(sgxHandle, mechanism, signHandle);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to initialize sign SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_sign(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char* data, unsigned long data_len,
    unsigned char* signature, unsigned long* signature_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_Sign");
    rv = p11->C_Sign(sgxHandle, data, data_len, signature, signature_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to sign in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_verifystart(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));

    OSAttribute osa = osObj->getAttribute(CKA_VALUE);
    CK_OBJECT_HANDLE signHandle = osa.getUnsignedLongValue();

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_VerifyInit");
    rv = p11->C_VerifyInit(sgxHandle, mechanism, signHandle);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to initialize verify in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_verify(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
    unsigned char* data, unsigned long data_len,
    unsigned char* signature, unsigned long* signature_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_Verify");
    rv = p11->C_Verify(sgxHandle, data, data_len, signature, *signature_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to verify SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_generatekey(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, 
    unsigned long count)
{
    if (tokenhandle == nullptr)
        return  CKR_ARGUMENTS_BAD;
    
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    CK_OBJECT_HANDLE internalKeyId;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_GenerateKey");
    rv = p11->C_GenerateKey(sgxHandle, mechanism, templ, count, &internalKeyId);
    if (rv != CKR_OK)
    {
        ERROR_MSG("SGX Toolkit failed to generate key in SGX Crypto API Toolkit %lu", rv);
        return rv;
    }

// used only for OSObject producedobjectptr
    OSObject* newObj = nullptr;
    rv = CryptoHandler::generateKey(*token, newObj, mechanism, templ, count);
    if (newObj && rv == CKR_OK) 
    {
        OSAttribute osa(internalKeyId);
        newObj->setAttribute(CKA_VALUE, osa);
        newObj->setAttribute(CKA_ID, phSession);

	    context->producedobjectptr(context, newObj, keytype_type::PUBLIC);
    }
    
    if (rv != CKR_OK)
        ERROR_MSG("Failed to generate key in SGX HW Token %lu", rv);

    return rv;
}

int32_t token_generatekeypair(tokenhandle_type tokenhandle, tokencontext_type context,CK_MECHANISM_PTR mechanism, 
    CK_ATTRIBUTE_PTR public_key_template, unsigned long public_key_attribute_count,
    CK_ATTRIBUTE_PTR private_key_template, unsigned long private_key_attribute_count)
{
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    CK_OBJECT_HANDLE ck_pubKeyId;
    CK_OBJECT_HANDLE ck_privKeyId;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_GenerateKeyPair");
    rv = p11->C_GenerateKeyPair(sgxHandle, 
        mechanism, 
        public_key_template, 
        public_key_attribute_count, 
        private_key_template,
        private_key_attribute_count, 
        &ck_pubKeyId, &ck_privKeyId);

    if (rv != CKR_OK)
    {
        ERROR_MSG("Failed to generate key pair in SGX Crypto API Toolkit %lu", rv);
        return rv;
    }

    OSObject* cPubKey = nullptr;
    OSObject* cPrivKey = nullptr;

// used only for OSObject producedobjectptr
    rv = CryptoHandler::generateKeyPair(*token, cPubKey, cPrivKey, mechanism,
            public_key_template, public_key_attribute_count,
            private_key_template, private_key_attribute_count);

    if (rv == CKR_OK) {
        // set public key handle and attribute
        OSAttribute pubOsa(ck_pubKeyId);
        cPubKey->setAttribute(CKA_IN_ENCLAVE, true);
        cPubKey->setAttribute(CKA_VALUE, pubOsa);
        cPubKey->setAttribute(CKA_ID, phSession);
        OSAttribute npbOsa = cPubKey->getAttribute(CKA_VALUE);
        context->producedobjectptr(context, cPubKey, keytype_type::PUBLIC);

        // set private key handle and attribute
        OSAttribute privOsa(ck_privKeyId);
        cPrivKey->setAttribute(CKA_IN_ENCLAVE, true);
        cPrivKey->setAttribute(CKA_VALUE, privOsa);
        cPrivKey->setAttribute(CKA_ID, phSession);
        OSAttribute npvOsa = cPrivKey->getAttribute(CKA_VALUE);
        context->producedobjectptr(context, cPrivKey, keytype_type::PRIVATE);
    }

    if (rv != CKR_OK)
        ERROR_MSG("Failed to generate key pair SGX HW Token %lu", rv);

    return rv;
}

int32_t token_wrapkey(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char* wrapped_key, unsigned long* wrapped_key_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    OSObject* wrappingKey = static_cast<OSObject*>(context->getdirectobjectptr(context));
    OSObject* wrappedKey = static_cast<OSObject*>(context->getsubjectobjectptr(context));

    if (wrappingKey == NULL_PTR)
    {
        ERROR_MSG("Wrapping key was empty in SGX HW Token %lu", CKR_WRAPPING_KEY_HANDLE_INVALID);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if (wrappedKey == NULL_PTR)
    {
        ERROR_MSG("Wrapped key was empty in SGX HW Token %lu", CKR_WRAPPED_KEY_INVALID);
        return CKR_OBJECT_HANDLE_INVALID;;
    }

    if (wrappedKey != NULL_PTR && wrappedKey->isValid()) 
    {        
        OSAttribute wrappingOsa = wrappingKey->getAttribute(CKA_VALUE);
        CK_OBJECT_HANDLE wrappingKeyHandle = wrappingOsa.getUnsignedLongValue();

        OSAttribute wrappedOsa = wrappedKey->getAttribute(CKA_VALUE);
        CK_OBJECT_HANDLE wrappedKeyHandle = wrappedOsa.getUnsignedLongValue();

        DEBUG_MSG("Calling SGX Crypto API Toolkit C_WrapKey");
        // pass ID of the wrapping key, and key-to-be-wrapped; receive wrapped key
        rv = p11->C_WrapKey(sgxHandle, mechanism, wrappingKeyHandle, wrappedKeyHandle, wrapped_key, wrapped_key_len);

        if (rv != CKR_OK)
            ERROR_MSG("Failed to wrap key SGX Crypto API Toolkit %lu", rv);
    }

    return rv;
}

int32_t token_unwrapkey(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char* wrapped_key, unsigned long wrapped_key_len, 
    CK_ATTRIBUTE* templ, unsigned long attribute_count)
{
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    OSObject* unwrappingKey = static_cast<OSObject*>(context->getdirectobjectptr(context));
    OSObject* newKey = static_cast<OSObject*>(context->getsubjectobjectptr(context));
    
    if (unwrappingKey == NULL_PTR)
    {
        ERROR_MSG("Wrapping key was empty in SGX HW Token %lu", CKR_UNWRAPPING_KEY_HANDLE_INVALID);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if (newKey == NULL_PTR)
    {
        ERROR_MSG("New key was empty in SGX HW Token %lu", CKR_KEY_HANDLE_INVALID);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    OSAttribute unwrappingOsa = unwrappingKey->getAttribute(CKA_VALUE);
    CK_OBJECT_HANDLE unwrappingKeyHandle = unwrappingOsa.getUnsignedLongValue();
    CK_OBJECT_HANDLE sgxUnwrappedKeyId;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_UnwrapKey");
    rv = p11->C_UnwrapKey(sgxHandle, mechanism, unwrappingKeyHandle, wrapped_key, wrapped_key_len, templ, attribute_count, &sgxUnwrappedKeyId);
    if (rv != CKR_OK || !sgxUnwrappedKeyId)
    {
        ERROR_MSG("Failed to unwrap key in SGX Crypto API Toolkit %lu", rv);
        return rv;
    }

// used only for OSObject producedobjectptr
    rv = CryptoHandler::unwrapKey(*token, *unwrappingKey, newKey, mechanism, templ, attribute_count, wrapped_key, wrapped_key_len);
    if (newKey && rv == CKR_OK) 
    {
        OSAttribute osa(sgxUnwrappedKeyId);
        newKey->setAttribute(CKA_VALUE, osa);

        // need to ensure that enclave destroys, instead of Object Store. 
        newKey->setAttribute(CKA_IN_ENCLAVE, true);
        newKey->setAttribute(CKA_ID, phSession);

        context->producedobjectptr(context, newKey, keytype_type::PUBLIC);
    }

    if (rv != CKR_OK)
        ERROR_MSG("Failed to unwrap key SGX HW Token %lu", rv);

    return rv;
}

int32_t token_derivekey(tokenhandle_type tokenhandle, tokencontext_type context,
    CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, unsigned long attribute_count)
{
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    SoftToken* token = static_cast<SoftToken*>(tokenhandle);
    if (token == NULL)
        return CKR_DATA_INVALID;

    OSObject* osObj = static_cast<OSObject*>(context->getdirectobjectptr(context));

    CK_OBJECT_HANDLE sgxDerviedKeyId;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DeriveKey");
    rv = p11->C_DeriveKey(sgxHandle, mechanism, NULL_PTR, templ, attribute_count, &sgxDerviedKeyId);
    if (rv != CKR_OK || !sgxDerviedKeyId)
    {
        ERROR_MSG("Failed to derive key in SGX Crypto API Toolkit %lu", rv);
        return rv;
    }

    return rv;
}

int32_t token_disposeobject(tokenhandle_type tokenhandle, tokencontext_type context)
{
    if (context == nullptr)
        return CKR_ARGUMENTS_BAD;
    
    DEBUG_MSG("SGX HW Token Disposing of object");
    
    OSObject* osObj = (OSObject *) context->getdirectobjectptr(context);
    if (osObj == NULL_PTR || !osObj->isValid())
        return CKR_OBJECT_HANDLE_INVALID;

    return CKR_OK;
}

int32_t token_seedrandom(tokenhandle_type tokenhandle, tokencontext_type context, 
    unsigned long seed_len, unsigned char* seed)
{    
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_SeedRandom");
    rv = p11->C_SeedRandom(sgxHandle, seed, seed_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to seed random in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_generaterandom(tokenhandle_type tokenhandle, tokencontext_type context, 
    unsigned long random_len, unsigned char* random_data)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_GenerateRandom");
    rv = p11->C_GenerateRandom(phSession, random_data, random_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to generate random in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_encryptupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
    unsigned char *data, unsigned long data_len, 
    unsigned char *encrypted_data, unsigned long *encrypted_data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_EncryptUpdate");
    rv = p11->C_EncryptUpdate(sgxHandle, data, data_len, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to update encrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_encryptfinal(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
    unsigned char *encrypted_data, unsigned long *encrypted_data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;
      
    DEBUG_MSG("Calling SGX Crypto API Toolkit C_EncryptFinal");
    rv = p11->C_EncryptFinal(sgxHandle, encrypted_data, encrypted_data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to finalize encrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_decryptupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
    unsigned char *encrypted_data, unsigned long encrypted_data_len, 
    unsigned char *data, unsigned long *data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DecryptUpdate");
    rv = p11->C_DecryptUpdate(sgxHandle, encrypted_data, encrypted_data_len, data, data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to update decrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_decryptfinal(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char *data, unsigned long *data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DecryptFinal");
    rv = p11->C_DecryptFinal(sgxHandle, data, data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to finalize decrypt in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_digestupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char *data, unsigned long data_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DigestUpdate");
    rv = p11->C_DigestUpdate(sgxHandle, data, data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to update digest in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_digestkey(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism)
{
    if (tokenhandle == nullptr)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;
    
    OSObject* keyObject = (OSObject *)context->getdirectobjectptr(context);
    if (keyObject == nullptr)
        return CKR_OBJECT_HANDLE_INVALID;
    
    OSAttribute nOsa = keyObject->getAttribute(CKA_VALUE);
    unsigned long keyHandle = nOsa.getUnsignedLongValue();

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DigestKey");
    rv = p11->C_DigestKey(sgxHandle, keyHandle);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to digest key in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_digestfinal(tokenhandle_type tokenhandle, tokencontext_type context, 
    unsigned char *digest, unsigned long *digest_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_DigestFinal");
    rv = p11->C_DigestFinal(sgxHandle, digest, digest_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to finalize digest in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_signupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char *data, unsigned long data_len)
{
    if (data == NULL || data_len == 0)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;
    
    DEBUG_MSG("Calling SGX Crypto API Toolkit C_SignUpdate");
    rv = p11->C_SignUpdate(sgxHandle, data, data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to update sign in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_signfinal(tokenhandle_type tokenhandle, tokencontext_type context, 
    unsigned char *signature, unsigned long *signature_len)
{
    if (signature == NULL || signature_len == NULL)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_SignFinal");
    rv = p11->C_SignFinal(sgxHandle, signature, signature_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to finalize sign in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_verifyupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
    unsigned char *data, unsigned long data_len)
{
    if (data == NULL || data_len == 0)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_VerifyUpdate");
    rv = p11->C_VerifyUpdate(sgxHandle, data, data_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to update verify in SGX Crypto API Toolkit %lu", rv);

    return rv;
}

int32_t token_verifyfinal(tokenhandle_type tokenhandle, tokencontext_type context, 
    unsigned char *signature, unsigned long *signature_len)
{
    if (signature == NULL || signature_len == NULL)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv = CKR_GENERAL_ERROR;
    CK_SESSION_HANDLE phSession;
    CK_SESSION_HANDLE sgxHandle;

    if ((rv = get_session_handle(context, &phSession, &sgxHandle)) != CKR_OK)
        return rv;

    DEBUG_MSG("Calling SGX Crypto API Toolkit C_VerifyFinal");
    rv = p11->C_VerifyFinal(sgxHandle, signature, *signature_len);
    if (rv != CKR_OK)
        ERROR_MSG("Failed to finalize verify in SGX Crypto API Toolkit %lu", rv);
    
    return rv;
}
