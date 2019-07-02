#ifndef _SOFTHSM_V2_SOFTTOKEN_SOFTTOKENEXTENSION_H
#define _SOFTHSM_V2_SOFTTOKEN_SOFTTOKENEXTENSION_H

#include <pkcs11.h>

#include "interface.h"

// these are functions not in the "token api" but maybe will be added
// they are here as a way to get full functionality from while keeping code separated

int32_t token_createtoken(tokenlib_type tokenlib, tokenhandle_type* tokenhandle);

int32_t token_encryptupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
            unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len);
int32_t token_encryptfinal(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
            unsigned char *encrypted_data, unsigned long *encrypted_data_len);

int32_t token_decryptupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism, 
            unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len);
int32_t token_decryptfinal(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
            unsigned char *data, unsigned long *data_len);

int32_t token_digestupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
            unsigned char *data, unsigned long data_len);
int32_t token_digestkey(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism);
int32_t token_digestfinal(tokenhandle_type tokenhandle, tokencontext_type context, unsigned char *digest, unsigned long *digest_len);

int32_t token_signupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
            unsigned char *data, unsigned long data_len);
int32_t token_signfinal(tokenhandle_type tokenhandle, tokencontext_type context, unsigned char *signature, unsigned long *signature_len);

int32_t token_verifyupdate(tokenhandle_type tokenhandle, tokencontext_type context, CK_MECHANISM_PTR mechanism,
            unsigned char *data, unsigned long data_len);
int32_t token_verifyfinal(tokenhandle_type tokenhandle, tokencontext_type context, unsigned char *signature, unsigned long *signature_len);

#endif // _SOFTHSM_V2_SOFTTOKEN_SOFTTOKENEXTENSION_H