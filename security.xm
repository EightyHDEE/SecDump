/*

SecDump by 80HD 2021
all credit is given where due.

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

void WLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *formattedString = [[NSString alloc] initWithFormat: format
                                                  arguments: args];
    va_end(args);
    [[NSFileHandle fileHandleWithStandardOutput]
        writeData: [formattedString dataUsingEncoding: NSNEXTSTEPStringEncoding]];
    
    NSError* err;
    NSString *content = [NSString stringWithContentsOfFile:@"/private/var/mobile/Media/log" encoding:NSASCIIStringEncoding error:&err];
    NSString *text = [NSString stringWithFormat:@"%@\n[%@]%@\n",content, getBundleName(), formattedString];
    [text writeToFile:@"/private/var/mobile/Media/log" atomically:YES encoding:NSASCIIStringEncoding error:&err];
}

/*
Cryptography and Digital Signatures

SecKeyGeneratePair
SecKeyEncrypt
SecKeyDecrypt
SecKeyRawSign
SecKeyRawVerify
SecKeyGetBlockSize
*/

// typedef uint32_t SecPadding;
// enum
// {
//    kSecPaddingNone      = 0,
//    kSecPaddingPKCS1     = 1,
//    kSecPaddingPKCS1MD2  = 0x8000,
//    kSecPaddingPKCS1MD5  = 0x8001,
//    kSecPaddingPKCS1SHA1 = 0x8002,
// };
// OSStatus SecKeyGeneratePair ( CFDictionaryRef parameters, SecKeyRef _Nullable *publicKey, SecKeyRef _Nullable *privateKey ); 

/*
OSStatus (*orig_SecKeyEncrypt) ( SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen ); 
OSStatus replaced_SecKeyEncrypt ( SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen ) {
    
    OSStatus ret = orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);

    WLog(@"SecKeyEncrypt   Key: %@", key);
    WLog(@"                Padding: %u", padding);
    WLog(@"                plainText: %s", plainText);
    WLog(@"                plainTextLen: %lu", plainTextLen);
    WLog(@"                cipherText: %s", cipherText);
    // WLog(@"                cipherTextLen: %@", cipherTextLen);

    return ret;
}
*/

/*
OSStatus (*orig_SecKeyDecrypt) ( SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen );
OSStatus replaced_SecKeyDecrypt ( SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen ) {
    
    OSStatus ret = orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);

    WLog(@"SecKeyDecrypt   Key: %@", key);
    WLog(@"                Padding: %u", padding);
    WLog(@"                cipherText: %s", cipherText);
    WLog(@"                cipherTextLen: %lu", cipherTextLen);
    WLog(@"                plainText: %s", plainText);

    return ret;
}
*/
/*
CFDataRef (*orig_SecKeyCopyPublicKey)(SecKeyRef privkey, SecKeyRef pub);
CFDataRef my_SecKeyCopyPublicKey(SecKeyRef privkey, SecKeyRef pub)
{
	@autoreleasepool
	{
    
    	CFDataRef r = orig_SecKeyCopyPublicKey(privkey, pub);
    	WLog(@"CopyPublicKey = %@ ", r);
    	return r;

	}
}
*/

OSStatus (*orig_SecKeyRawSign) ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen );
OSStatus replaced_SecKeyRawSign ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen ) 
{
    
    @autoreleasepool
    
    {
    
    	OSStatus ret = orig_SecKeyRawSign(key, padding, dataToSign, dataToSignLen, sig, sigLen);
		NSLog(@"SecKeyRawSign was called!");
		WLog(@"SecKeyRawSign was called!");


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
		CFDataRef r = orig_SecKeyCreateSignature(key, algorithm, dataToSign, error);
		NSLog(@"SecKeyCreateSignature was called!");
		WLog(@"SecKeyCreateSignature was called!");
		
		CFErrorRef *error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(key, error);
		NSData* datakey = (__bridge NSData*) data;
		NSData* datasign = (__bridge NSData*) dataToSign;
		NSData* datasig = (__bridge NSData*) r;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];
   		NSString *signb64ref = [datasign base64EncodedStringWithOptions:0];
   		NSString *sigb64ref = [datasig base64EncodedStringWithOptions:0];



		WLog(@"SecKeyCreateSignature: %@ ", sigb64ref);
		WLog(@"key: %@ ", base64ref);
		WLog(@"data: %@ ", signb64ref);

		return r;
		}
		
}

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
		NSLog(@"SecKeyCreateRSAPrivateKey was called!");
		WLog(@"SecKeyCreateRSAPrivateKey was called!");

// Declare the original instance so that we can represent it in the function  with a variable to save time
//

		SecKeyRef r = orig_SecKeyCreateRSAPrivateKey(allocator, keyData, keyDataLength, encoding);

// Create a Persistent reference to the key

		CFErrorRef *error = nil;
		CFDataRef data = SecKeyCopyExternalRepresentation(r, error);
		NSData* datakey = (__bridge NSData*) data;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];

	
// Log the return and parameters 
//	
		WLog(@"SecKeyCreateRSAPrivateKey = %@", base64ref);	
	
// Return the original function
//
		return r;
		
		}

}

OSStatus (*orig_SecKeyGeneratePair)(CFDictionaryRef parameters, SecKeyRef  _Nullable *publicKey, SecKeyRef  _Nullable *privateKey);
OSStatus replaced_SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef  _Nullable *publicKey, SecKeyRef  _Nullable *privateKey)
{
	@autoreleasepool
	{
		OSStatus r = orig_SecKeyGeneratePair(parameters, publicKey, privateKey);
		NSLog(@"SecKeyGeneratePair was called!");
		WLog(@"SecKeyGeneratePair was called!");
		
		CFErrorRef *error = nil;
		CFDataRef data = SecKeyCopyExternalRepresentation(*privateKey, error);
		NSData* datakey = (__bridge NSData*) data;
   		NSString *base64ref = [datakey base64EncodedStringWithOptions:0];
  		  
  		WLog(@"SecKeyGeneratePair = %@.", base64ref);

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

/*		Do we need this function?

OSStatus (*orig_SecKeyRawVerify) ( SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen );
OSStatus replaced_SecKeyRawVerify ( SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen ) {
    
    OSStatus ret = orig_SecKeyRawVerify(key, padding, signedData, signedDataLen, sig, sigLen);

    WLog(@"SecKeyRawVerify   Key: %@", key);
    WLog(@"                Padding: %u", padding);
    WLog(@"                signedData: %s", signedData);
    WLog(@"                signedDataLen: %lu", signedDataLen);
    WLog(@"                sig: %s", sig);

    return ret;
}
*/
SecKeyRef (*orig_SecKeyCopyAttestationKey)(SecKeyAttestationKeyType keyType, CFErrorRef *error);
SecKeyRef replaced_SecKeyCopyAttestationKey(SecKeyAttestationKeyType keyType, CFErrorRef *error){

	@autoreleasepool

	{
		SecKeyRef r = orig_SecKeyCopyAttestationKey(keyType, error);
		CFErrorRef * error = nil;
		CFDataRef _Nullable data = SecKeyCopyExternalRepresentation(r, error);
		NSData* datakey = (__bridge NSData*) data;
		NSString *base64data = [datakey base64EncodedStringWithOptions:0];
		WLog(@"CopyAttestationKey = %@", base64data);

		return r;
    }

}
/*
SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef privkey, SecKeyRef pub);
SecKeyRef replaced_SecKeyCopyPublicKey(SecKeyRef privkey, SecKeyRef pub)
{
    SecKeyRef r = orig_SecKeyCopyPublicKey(privkey, pub);
    WLog(@"CopyPublicKey = %@ ", r);
    return r;
}
*/

CFDataRef (*orig_SecKeyCreateAttestation)(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef *error);
CFDataRef replaced_SecKeyCreateAttestation(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef *error)
{
    CFDataRef r = orig_SecKeyCreateAttestation(key, keyToAttest, error);
    NSData* datakey = (__bridge NSData*) r;
    NSString *base64cert = [datakey base64EncodedStringWithOptions:0];
    WLog(@"CreateAttestation = %@.", base64cert);
    return r;
}
__attribute__((constructor)) static void initialize() 
{

MSHookFunction(SecKeyCopyAttestationKey, replaced_SecKeyCopyAttestationKey, &orig_SecKeyCopyAttestationKey);
MSHookFunction(SecKeyCreateAttestation, replaced_SecKeyCreateAttestation, &orig_SecKeyCreateAttestation);
MSHookFunction(SecKeyRawSign, replaced_SecKeyRawSign, &orig_SecKeyRawSign);
MSHookFunction(SecKeyCreateRSAPrivateKey, replaced_SecKeyCreateRSAPrivateKey, &orig_SecKeyCreateRSAPrivateKey);
MSHookFunction(SecKeyGeneratePair, replaced_SecKeyGeneratePair, &orig_SecKeyGeneratePair);
MSHookFunction(SecKeyCreateSignature, replaced_SecKeyCreateSignature, &orig_SecKeyCreateSignature);
//MSHookFunction(SecKeyCopyPublicKey, replaced_SecKeyCopyPublicKey, &orig_SecKeyCopyPublicKey);

}
