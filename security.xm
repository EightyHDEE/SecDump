/*

Forked and modified by 80HD 2021
all credit is given where due.

 File Description:
  
	**********************************************************************************
	** Security Framework Reference Certificate, Key, and Trust Services Reference  **
	**********************************************************************************

	https://developer.apple.com/library/ios/documentation/Security/Reference/certifkeytrustservices/index.html#//apple_ref/doc/uid/TP30000157

	Swizzler: Thanks to https://raw.githubusercontent.com/vtky/Swizzler/
	
	WLog: Thanks to BlueDog
	
    SSL Pinning Bypass:
        Thanks to Alban Diquet - https://github.com/nabla-c0d3 and iSECPartners for the iOS Killswitch Project https://github.com/iSECPartners/ios-ssl-kill-switch

*/
#include "swizzler.common.h"
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import "substrate.h"
#import "SecRSAKey.h"
#import "SecKeyPriv.h"

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

OSStatus (*orig_SecKeyRawSign) ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen );
OSStatus replaced_SecKeyRawSign ( SecKeyRef key, SecPadding padding, const uint8_t *dataToSign, size_t dataToSignLen, uint8_t *sig, size_t *sigLen ) {
    
    OSStatus ret = orig_SecKeyRawSign(key, padding, dataToSign, dataToSignLen, sig, sigLen);

    WLog(@"SecKeyRawSign   Key: %@", key);
    WLog(@"                Padding: %u", padding);
    WLog(@"                dataToSign: %s", dataToSign);
    WLog(@"                dataToSignLen: %lu", dataToSignLen);
    WLog(@"                sig: %s", sig);

    return ret;
}

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

SecKeyRef (*orig_SecKeyCreateRSAPrivateKey)(CFAllocatorRef allocator,
    const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding);
SecKeyRef replaced_SecKeyCreateRSAPrivateKey(CFAllocatorRef allocator,
    const uint8_t *keyData, CFIndex keyDataLength,
    SecKeyEncoding encoding)
{

// Declare the function was called first in case the data is not represented
//
	WLog(@"SecKeyCreateRSAPrivateKey was called!");

// Declare the original instance so that we can represent it in the function  with a variable to save time
//
	SecKeyRef r = orig_SecKeyCreateRSAPrivateKey(allocator, keyData, keyDataLength, encoding);

// Convert SecKeyRef to Data representation
//
	CFDataRef externKey = SecKeyCopyExternalRepresentation(r, nil);


// Log the return and parameters 
//	
	WLog(@"SecKeyCreateRSAPrivateKey: %@", externKey);
	WLog(@"Allocator: %@", allocator);
	WLog(@"keyData: %@", keyData);
	WLog(@"keyDataLength: %@", keyDataLength);
	WLog(@"encoding: %@", encoding);
	
// Return the original function
//
	return r;
}

OSStatus (*orig_SecKeyGeneratePair)(CFDictionaryRef parameters, SecKeyRef  _Nullable *publicKey, SecKeyRef  _Nullable *privateKey);
OSStatus replaced_SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef  _Nullable *publicKey, SecKeyRef  _Nullable *privateKey)
{
	OSStatus r = orig_SecKeyGeneratePair(parameters, publicKey, privateKey);
	WLog(@"SecKeyGeneratePair was called!");
	WLog(@"OSStatus: %@", r);
	WLog(@"parameters: %@", parameters);
	WLog(@"publicKey: %@", publicKey);
	WLog(@"privateKey: %@", privateKey);
	return r;
}

/*
Managing Trust

SecTrustCopyCustomAnchorCertificates
SecTrustCopyExceptions
SecTrustCopyProperties
SecTrustCopyPolicies
SecTrustCopyPublicKey
SecTrustCreateWithCertificates
SecTrustEvaluate
SecTrustEvaluateAsync
SecTrustGetCertificateCount
SecTrustGetCertificateAtIndex
SecTrustGetTrustResult
SecTrustGetVerifyTime
SecTrustSetAnchorCertificates
SecTrustSetAnchorCertificatesOnly
SecTrustSetExceptions
SecTrustSetPolicies
SecTrustSetVerifyDate
*/
OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    
    OSStatus ret = orig_SecTrustEvaluate(trust, result);
    // Actually, this certificate chain is trusted
    *result = kSecTrustResultUnspecified;

    WLog(@"SecTrustEvaluate SSL Pinning Bypass");

    return ret;
}


__attribute__((constructor)) static void initialize() {
MSHookFunction(SecKeyEncrypt, replaced_SecKeyEncrypt, &orig_SecKeyEncrypt);
MSHookFunction(SecKeyDecrypt, replaced_SecKeyDecrypt, &orig_SecKeyDecrypt);
MSHookFunction(SecKeyRawSign, replaced_SecKeyRawSign, &orig_SecKeyRawSign);
MSHookFunction(SecKeyRawVerify, replaced_SecKeyRawVerify, &orig_SecKeyRawVerify);
MSHookFunction(SecKeyCreateRSAPrivateKey, replaced_SecKeyCreateRSAPrivateKey, &orig_SecKeyCreateRSAPrivateKey);
MSHookFunction(SecKeyGeneratePair, replaced_SecKeyGeneratePair, &orig_SecKeyGeneratePair);
}

/*
#define InstallHook(funcname) { MSHookFunction((void*)funcname, (void *)replaced_##funcname, (void**)&orig_##funcname); }
#define InstallHook_basic(funcname) MSHookFunction((void*)funcname, (void *)replaced_##funcname, (void**)&orig_##funcname)
#define InstallHook_FindSymbol(funcname) { MSHookFunction(MSFindSymbol(NULL, "_"#funcname), (void *)replaced_##funcname, (void**)&orig_##funcname); }


void Security_hooks()
{
//	NSMutableDictionary *plist = [[NSMutableDictionary alloc] initWithContentsOfFile:@PREFERENCEFILE];

    InstallHook(SecKeyEncrypt);
    InstallHook(SecKeyDecrypt);
    InstallHook(SecKeyRawSign);
    InstallHook(SecKeyRawVerify);
    InstallHook(SecKeyCreateRSAPrivateKey);
	InstallHook(SecKeyGeneratePair);
	
	
	if (disableSSLPinning())
    {
    	InstallHook(SecTrustEvaluate);
    }

}
*/
