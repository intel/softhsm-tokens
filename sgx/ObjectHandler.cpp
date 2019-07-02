#include "ObjectHandler.h"

#include "OSObject.h"
#include "P11Objects.h"
#include "ObjectFunctions.h"

CK_RV ObjectHandler::createObject(SoftToken& token, OSObject*& obj, CK_ATTRIBUTE_PTR templ, unsigned long count, int op)
{
	obj = token.createObject();
	if (obj == nullptr)
		return CKR_GENERAL_ERROR;
	CK_RV rv = ObjectFunctions::createObject(&token, *obj, templ, count, op);
	return rv;
}

CK_RV ObjectHandler::copyObject(SoftToken& token, OSObject& oldObj, OSObject*& newObj, CK_ATTRIBUTE_PTR templ, unsigned long count)
{
	newObj = token.createObject();
	if (newObj == nullptr)
		return CKR_GENERAL_ERROR;
	return ObjectFunctions::copyObject(&token, oldObj, templ, count, *newObj);
}

CK_RV ObjectHandler::destroyObject(OSObject* obj)
{
	CK_RV rv = CKR_OK;
	if (obj)
		rv = ObjectFunctions::destroyObject(*obj);
	obj = nullptr;
	return rv;
}

CK_RV ObjectHandler::getAttributeValue(SoftToken& token, OSObject& obj, CK_ATTRIBUTE_PTR templ, unsigned long count)
{
	return ObjectFunctions::getAttributeValue(&token, obj, templ, count);
}

CK_RV ObjectHandler::setAttributeValue(SoftToken& token, OSObject& obj, CK_ATTRIBUTE_PTR templ, unsigned long count)
{
	return ObjectFunctions::setAttributeValue(&token, obj, templ, count);
}

CK_RV ObjectHandler::findObjects(SoftToken &token, CK_ATTRIBUTE_PTR templ, unsigned long count, std::set<OSObject*>& matchingObjects)
{
	std::set<OSObject*> allObjects;
	token.getObjects(allObjects);

	for (const auto osObj : allObjects)
	{
		bool bAttrMatch = false;
		CK_RV rv = ObjectFunctions::matchObject(&token, templ, count, *osObj, bAttrMatch);
		if(rv == CKR_OK && bAttrMatch)
		{
			matchingObjects.insert(osObj);
		}
	}

	return CKR_OK;
}
