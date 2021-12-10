/*

	SecDump by 80HD 2021
	
	All credit is given where due.

 File Description:
  
	**********************************************************************************
	
	WLog: Thanks to BlueDog
	

*/
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import "substrate.h"
#import "SecRSAKey.h"
#import "SecKeyPriv.h"
#import <Security/SecKey.h>
#import "SecECKey.h"


// Setup WLog logging to file by BlueDog

// getBundleName to label the originating process
NSString* getBundleName()
{
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    
    if(mainBundle != NULL)
    {
        CFStringRef bundleIdentifierCF = CFBundleGetIdentifier(mainBundle);
        return (__bridge NSString*)bundleIdentifierCF;
    }

    return nil;
}

// Setup the WLog function to replace NSLog (NSLog is deprecated and you probably won't get console readouts with it)

void WLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *formattedString = [[NSString alloc] initWithFormat: format
                                                  arguments: args];
    va_end(args);
    [[NSFileHandle fileHandleWithStandardOutput]
        writeData: [formattedString dataUsingEncoding: NSNEXTSTEPStringEncoding]];
    
// You can change the location and name of the log here

    NSError* err;
    NSString *content = [NSString stringWithContentsOfFile:@"/private/var/mobile/Media/log" encoding:NSASCIIStringEncoding error:&err];
    NSString *text = [NSString stringWithFormat:@"%@\n[%@]%@\n",content, getBundleName(), formattedString];
    [text writeToFile:@"/private/var/mobile/Media/log" atomically:YES encoding:NSASCIIStringEncoding error:&err];
}




// Begin Security hooks
// If you're going to be bad, also be invisible! 

SecKeyRef (*orig_SecKeyCreateRSAPrivateKey)(CFAllocatorRef allocator,
     const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding);
SecKeyRef replaced_SecKeyCreateRSAPrivateKey(CFAllocatorRef allocator,
     const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding)
{
// setup the pool to automatically handle retain and release
	@autoreleasepool
	
		{
// Declare the function was called first in case the data is not represented
//
		WLog(@"SecKeyCreateRSAPrivateKey was called!");
		NSLog(@"SecKeyCreateRSAPrivateKey was called!");

// Declare the original instance so that we can represent it in the function  with a variable to save time
//

		SecKeyRef r = orig_SecKeyCreateRSAPrivateKey(allocator, keyData, keyDataLength, encoding);

// Create a Persistent reference to the key

		CFErrorRef *error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(r, error);
		NSData* datakey = (__bridge NSData*) data;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];

	
// Log the return and parameters 
//	
		WLog(@"SecKeyCreateRSAPrivateKey = %@", base64ref);
		WLog(@"SecKeyCreateRSAPrivateKey orig = %@", r);
	
// Return the original function
//
		return r;
		
		}

}

OSStatus (*orig_SecKeySignDigest)(
       SecKeyRef           key,            /* Private key */
       const SecAsn1AlgId  *algId,         /* algorithm oid/params */
       const uint8_t       *digestData,    /* signature over this digest */
       size_t              digestDataLen,  /* length of digestData */
       uint8_t             *sig,           /* signature, RETURNED */
       size_t              *sigLen);       /* IN/OUT */
OSStatus replaced_SecKeySignDigest(
       SecKeyRef           key,            /* Private key */
       const SecAsn1AlgId  *algId,         /* algorithm oid/params */
       const uint8_t       *digestData,    /* signature over this digest */
       size_t              digestDataLen,  /* length of digestData */
       uint8_t             *sig,           /* signature, RETURNED */
       size_t              *sigLen)       /* IN/OUT */

{

	WLog(@"SecKeySignDigest was called!");
	OSStatus r = orig_SecKeySignDigest(key, algId, digestData, digestDataLen, sig, sigLen);
	
	CFErrorRef * error = nil;
	CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(key, error);
	
	NSData* datakey = (__bridge NSData*) data;
	NSString *base64ref = [datakey base64EncodedStringWithOptions:0];
	
	WLog(@"SecKeySignDigest with key: %@", base64ref);
	WLog(@"SecKeySignDigest digestData: %@", digestData);
	WLog(@"SecKeySignDigest signature: %@", sig);

	return r;

}
        



OSStatus (*orig_SecKeyRawSign) ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen );
OSStatus replaced_SecKeyRawSign ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen ) 
{
    
    @autoreleasepool
    
    {
    
		WLog(@"SecKeyRawSign was called!");
		NSLog(@"SecKeyRawSign was called!");
    
    	OSStatus ret = orig_SecKeyRawSign(key, padding, dataToSign, dataToSignLen, sig, sigLen);



		CFErrorRef *error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(key, error);
    	
   		WLog(@"SecKeyRawSign   Key: %@", data);
		WLog(@"dataToSign: %@", dataToSign);
    	return ret;

	}
	
}



CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef  _Nullable *error);
CFDataRef replaced_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef  _Nullable *error)
{

	@autoreleasepool
	
	{
		NSLog(@"SecKeyCreateSignature was called!");
		WLog(@"SecKeyCreateSignature was called!");
		
		CFDataRef r = orig_SecKeyCreateSignature(key, algorithm, dataToSign, error);
		
		
		// try to move the key to keychain
		NSData* tag = [@"com.thewitchdoctors.signing.key" dataUsingEncoding:NSUTF8StringEncoding];
		NSDictionary* addquery = @{ (id)kSecValueRef: (__bridge id)key,
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag,
                           };

		OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addquery, NULL);
		
		if (status != errSecSuccess)
		{WLog(@"Failed to enter Signing Key to keychain.");}
		
		else {WLog(@"Signing Key entered to keychain!");}
		
		CFErrorRef *error = nil;
		
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(key, error);
		NSData* datakey = (__bridge NSData*) data;
		NSData* datasign = (__bridge NSData*) dataToSign;
		NSData* datasig = (__bridge NSData*) r;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];
   		NSString *signb64ref = [datasign base64EncodedStringWithOptions:0];
   		NSString *sigb64ref = [datasig base64EncodedStringWithOptions:0];

		
		if (data != nil) {WLog(@"key: %@ ", base64ref); WLog(@"data to sign: %@ ", signb64ref); WLog(@"signature: %@ ", sigb64ref);}
		
		else if (key == nil) {WLog(@"Key for signature was not captured :( ");}

		else {WLog(@"No base64 representation available, using original reference: \n %@ ", key); WLog(@"data to sign: %@ ", signb64ref); WLog(@"signature: %@ ", sigb64ref);}
		
		return r;
	}
		
}


OSStatus (*orig_SecKeyGeneratePair)(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey);
OSStatus replaced_SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey)

{

	@autoreleasepool

	{
	
		WLog(@"SecKeyGeneratePair was called!");
		NSLog(@"SecKeyGeneratePair was called!");

		OSStatus r = orig_SecKeyGeneratePair(parameters, publicKey, privateKey);
		
		CFErrorRef *error = nil;
		CFDataRef data = SecKeyCopyExternalRepresentation(*privateKey, error);
		NSData* datakey = (__bridge NSData*) data;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];
  		  
  		if(data != nil)
  		
  			{WLog(@"SecKeyGeneratePair = %@", base64ref);}
  		
  		else
  			{WLog(@"SecKeyGeneratePair reports null!");}
  			
		return r;  		
	}

}



/*		Do we need this function?

OSStatus (*orig_SecIdentityCopyPrivateKey)(SecIdentityRef identityRef, SecKeyRef  _Nullable *privateKeyRef);
OSStatus replaced_SecIdentityCopyPrivateKey(SecIdentityRef identityRef, SecKeyRef  _Nullable *privateKeyRef)
{
	OSStatus r = orig_SecIdentityCopyPrivateKey(identityRef, privateKeyRef);
	WLog(@"identity: %@", identityRef);
	WLog(@"private: %@", privateKeyRef);
	return r;
}
*/


SecKeyRef (*orig_SecKeyCopyAttestationKey)(SecKeyAttestationKeyType keyType, CFErrorRef *error);
SecKeyRef replaced_SecKeyCopyAttestationKey(SecKeyAttestationKeyType keyType, CFErrorRef *error)
{

	@autoreleasepool

	{
		WLog(@"SecKeyCopyAttestationKey was called!");
		NSLog(@"SecKeyCopyAttestationKey was called!");

		SecKeyRef r = orig_SecKeyCopyAttestationKey(keyType, error);
		
		
		CFErrorRef * error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(r, error);
		NSData* datakey = (__bridge NSData*) data;
		NSString *base64data = [datakey base64EncodedStringWithOptions:0];
				
		if (data != nil)
		
			{WLog(@"AttestationKey b64 = %@", base64data);
			WLog(@"AttestationKey data = %@", data);}
			
		else if (r == nil) {WLog(@"SecKeyCopAttestationKey was not captured");} 
			
		else {WLog(@"SecKeyCopyAttestationKey orig = %@", r);}
		
		return r;
    	
    }

}

CFDataRef (*orig_SecKeyCopyExternalRepresentation)(SecKeyRef key, CFErrorRef *error);
CFDataRef replaced_SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error)

{
	@autoreleasepool

		{
			WLog(@"SecKeyCopyExternalRepresentation was called!");
			NSLog(@"SecKeyCopyExternalRepresentation was called!");


			CFDataRef r = orig_SecKeyCopyExternalRepresentation(key, error);
			NSData* datakey = (__bridge NSData*) r;
			NSString *base64data = [datakey base64EncodedStringWithOptions:0];
			
			if (datakey != nil)
			{
				WLog(@"SecKeyCopyExternalRepresentation: %@", base64data);
			}
			
			else if (r == nil) {WLog(@"SecKeyCopyExternalRepresentation was not captured");} 
			
			else {WLog(@"SecKeyCopyExternalRepresentation orig: %@", r);}
			
			return r;
		}

}

CFDataRef (*orig_SecKeyCreateAttestation)(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef *error);
CFDataRef replaced_SecKeyCreateAttestation(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef *error)
{
	
	@autoreleasepool
	
	{
		WLog(@"SecKeyCreateAttestation was called!");
		NSLog(@"SecKeyCreateAttestation was called!");
		
		CFDataRef r = orig_SecKeyCreateAttestation(key, keyToAttest, error);
	
		
		CFErrorRef * error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(keyToAttest, error);
		
		NSData* b64key = (__bridge NSData*) data;
		NSData* cert = (__bridge NSData*) r;
		NSString *base64key = [b64key base64EncodedStringWithOptions:0];
		NSString *base64cert = [cert base64EncodedStringWithOptions:0];
		
		if (data != nil)
		{
			WLog(@"Create Attestation with key = %@", base64key);
			WLog(@"Attestation = %@", base64cert);
		}
		
		else if (r == nil) {WLog(@"SecKeyCreateAttestation is encrypted!");} 
		
		else  {WLog(@"SecKeyCreateAttestation orig: %@", r); WLog(@"Key to attest: %@", keyToAttest); WLog(@"Key: %@", key);} 
		
		return r;
	
	}
	
}

SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef parameters, CFErrorRef  _Nullable *error);
SecKeyRef replaced_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef  _Nullable *error)
{
	@autoreleasepool
	{
	
		WLog(@"SecKeyCreateRandomKey was called!");
		NSLog(@"SecKeyCreateRandomKey was called!");
		
		SecKeyRef r = orig_SecKeyCreateRandomKey(parameters, error);
		
		
		NSData* tag = [@"com.thewitchdoctors.activation.key" dataUsingEncoding:NSUTF8StringEncoding];
		NSDictionary* addquery = @{ (id)kSecValueRef: (__bridge id)r,
                            (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: tag,
                           };

		OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addquery, NULL);
		
		if (status != errSecSuccess)
		{WLog(@"Failed to enter Random Key to keychain.");}
		
		else {WLog(@"Random Key entered to keychain!");}
		
		WLog(@"SecKeyCreateRandomKey Orig parameters: %@", parameters);		
		WLog(@"SecKeyCreateRandomKey Orig key: %@",r);
			
		return r;
	}
}

SecKeyRef (*orig_SecKeyCreateECPrivateKey)(CFAllocatorRef allocator,
    const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding);
SecKeyRef replaced_SecKeyCreateECPrivateKey(CFAllocatorRef allocator,
    const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding)
{

	@autoreleasepool
	{
		WLog(@"SecKeyCreateECPrivateKey was called!");
		
		SecKeyRef r= orig_SecKeyCreateECPrivateKey(allocator, keyData, keyDataLength, encoding);
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(r, nil);
		
		if (data != nil)
		{WLog(@"SecKeyCreateECPrivateKey: %@", data);}
		else 
		{WLog(@"SecKeyCreateECPrivateKey orig: %@", r);}
		return r;
		
	}

}


__attribute__((constructor)) static void initialize() 
{
MSHookFunction(SecKeyCreateECPrivateKey, replaced_SecKeyCreateECPrivateKey, &orig_SecKeyCreateECPrivateKey);
MSHookFunction(SecKeyCreateRandomKey, replaced_SecKeyCreateRandomKey, &orig_SecKeyCreateRandomKey);


MSHookFunction(SecKeySignDigest, replaced_SecKeySignDigest, &orig_SecKeySignDigest);
MSHookFunction(SecKeyCopyAttestationKey, replaced_SecKeyCopyAttestationKey, &orig_SecKeyCopyAttestationKey);
MSHookFunction(SecKeyCreateAttestation, replaced_SecKeyCreateAttestation, &orig_SecKeyCreateAttestation);
MSHookFunction(SecKeyRawSign, replaced_SecKeyRawSign, &orig_SecKeyRawSign);
MSHookFunction(SecKeyCreateRSAPrivateKey, replaced_SecKeyCreateRSAPrivateKey, &orig_SecKeyCreateRSAPrivateKey);
MSHookFunction(SecKeyGeneratePair, replaced_SecKeyGeneratePair, &orig_SecKeyGeneratePair);
MSHookFunction(SecKeyCreateSignature, replaced_SecKeyCreateSignature, &orig_SecKeyCreateSignature);
MSHookFunction(SecKeyCopyExternalRepresentation, replaced_SecKeyCopyExternalRepresentation, &orig_SecKeyCopyExternalRepresentation);

}
