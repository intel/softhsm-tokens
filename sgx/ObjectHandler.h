#ifndef _SOFTHSM_V2_SOFTTOKEN_OBJECTHANDLER_H
#define _SOFTHSM_V2_SOFTTOKEN_OBJECTHANDLER_H

#include <pkcs11.h>

#include "P11Attributes.h"

#include <set>

// forward declarations
class SoftToken;
class OSObject;

// might only be static functions here so could probably skip the class
// this could also be placed in token instead
class ObjectHandler
{
public:
	static CK_RV createObject(SoftToken& token, OSObject*& obj, CK_ATTRIBUTE_PTR templ, unsigned long count, int op = OBJECT_OP_CREATE);
	static CK_RV copyObject(SoftToken& token, OSObject& oldObj, OSObject*& newObj, CK_ATTRIBUTE_PTR templ, unsigned long count);
	static CK_RV destroyObject(OSObject* obj);

	static CK_RV getAttributeValue(SoftToken& token, OSObject& obj, CK_ATTRIBUTE_PTR templ, unsigned long count);
	static CK_RV setAttributeValue(SoftToken& token, OSObject& obj, CK_ATTRIBUTE_PTR templ, unsigned long count);

	// might need session data here too
	static CK_RV findObjects(SoftToken& token, CK_ATTRIBUTE_PTR templ, unsigned long count, std::set<OSObject*>& matchingObjects);
};


#endif //_SOFTHSM_V2_SOFTTOKEN_OBJECTHANDLER_H
