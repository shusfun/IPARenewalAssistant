//
//  keychain.mm
//  AltSign CLI
//

#import "keychain.h"

#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BOOL gKeychainDenied = NO;

BOOL ALTKeychainAccessWasDenied(void)
{
    return gKeychainDenied;
}

void ALTKeychainMarkAccessDenied(void)
{
    gKeychainDenied = YES;
}

BOOL ALTKeychainOSStatusIsDenied(OSStatus status)
{
    switch (status) {
        case errSecUserCanceled:
        case errSecAuthFailed:
        case errSecInteractionNotAllowed:
        case errSecMissingEntitlement:
            return YES;
        default:
            return NO;
    }
}

ALTKeychainStatus ALTKeychainStatusFromOSStatus(OSStatus status)
{
    if (status == errSecSuccess) {
        return ALTKeychainStatusFound;
    }
    if (status == errSecItemNotFound) {
        return ALTKeychainStatusNotFound;
    }
    if (ALTKeychainOSStatusIsDenied(status)) {
        ALTKeychainMarkAccessDenied();
        return ALTKeychainStatusDenied;
    }
    switch (status) {
        case errSecNotAvailable:
        case errSecNoSuchKeychain:
        case errSecInvalidKeychain:
        case errSecReadOnly:
            return ALTKeychainStatusUnavailable;
        default:
            return ALTKeychainStatusUnavailable;
    }
}

static NSString *ExecutablePath(void)
{
    char path[PATH_MAX];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) {
        return [[NSProcessInfo processInfo] arguments].firstObject;
    }
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL) {
        return [NSString stringWithUTF8String:resolved];
    }
    return [NSString stringWithUTF8String:path];
}

static void AddTrustedApplication(NSMutableArray *trusted, NSString *path)
{
    if (path.length == 0 || !trusted) return;
    SecTrustedApplicationRef app = NULL;
    if (SecTrustedApplicationCreateFromPath(path.fileSystemRepresentation, &app) != errSecSuccess || !app) {
        return;
    }
    [trusted addObject:CFBridgingRelease(app)];
}

static SecAccessRef CreateRestrictedAccess(NSString *label)
{
    NSMutableArray *trusted = [NSMutableArray array];
    NSString *helper = ExecutablePath();
    AddTrustedApplication(trusted, helper);

    NSRange resources = [helper rangeOfString:@"/Contents/Resources/"];
    if (resources.location != NSNotFound) {
        NSString *appBundle = [helper substringToIndex:resources.location];
        if ([appBundle.pathExtension.lowercaseString isEqualToString:@"app"]) {
            NSString *macosDir = [appBundle stringByAppendingPathComponent:@"Contents/MacOS"];
            NSArray<NSString *> *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:macosDir error:nil];
            for (NSString *name in contents) {
                AddTrustedApplication(trusted, [macosDir stringByAppendingPathComponent:name]);
            }
        }
    }

    SecAccessRef access = NULL;
    CFArrayRef trustedRef = trusted.count > 0 ? (__bridge CFArrayRef)trusted : NULL;
    if (SecAccessCreate((__bridge CFStringRef)label, trustedRef, &access) != errSecSuccess) {
        return NULL;
    }
    return access;
}

static NSDictionary *ItemQuery(NSString *service, NSString *account)
{
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service
    } mutableCopy];
    if (account.length > 0) {
        query[(__bridge id)kSecAttrAccount] = account;
    }
    return query;
}

ALTKeychainStatus ALTKeychainLoadData(NSString *service,
                                      NSString *account,
                                      BOOL allowUI,
                                      NSData **outData)
{
    if (outData) *outData = nil;
    if (gKeychainDenied) {
        return ALTKeychainStatusDenied;
    }
    if (service.length == 0 || account.length == 0) {
        return ALTKeychainStatusNotFound;
    }

    NSMutableDictionary *query = [ItemQuery(service, account) mutableCopy];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    if (!allowUI) {
        query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
    }

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        if (outData) {
            *outData = CFBridgingRelease(result);
        } else {
            CFRelease(result);
        }
        return ALTKeychainStatusFound;
    }
    if (result) CFRelease(result);
    ALTKeychainStatus mapped = ALTKeychainStatusFromOSStatus(status);
    if (mapped == ALTKeychainStatusFound) {
        return ALTKeychainStatusNotFound;
    }
    return mapped;
}

BOOL ALTKeychainSaveData(NSString *service, NSString *account, NSData *data, NSString *label)
{
    if (gKeychainDenied) return NO;
    if (service.length == 0 || account.length == 0 || data.length == 0) return NO;

    NSDictionary *query = ItemQuery(service, account);
    NSDictionary *update = @{(__bridge id)kSecValueData: data};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    if (status == errSecSuccess) {
        return YES;
    }
    if (status != errSecItemNotFound) {
        if (ALTKeychainOSStatusIsDenied(status)) {
            ALTKeychainMarkAccessDenied();
        }
        return NO;
    }

    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge id)kSecValueData] = data;
    NSString *accessLabel = label.length > 0 ? label : service;
    SecAccessRef access = CreateRestrictedAccess(accessLabel);
    if (access) {
        item[(__bridge id)kSecAttrAccess] = (__bridge id)access;
    }
    status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    if (access) CFRelease(access);
    if (status == errSecDuplicateItem) {
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    }
    if (status != errSecSuccess && ALTKeychainOSStatusIsDenied(status)) {
        ALTKeychainMarkAccessDenied();
    }
    return status == errSecSuccess;
}

void ALTKeychainDeleteItems(NSString *service, NSString *account)
{
    if (service.length == 0) return;
    SecItemDelete((__bridge CFDictionaryRef)ItemQuery(service, account));
}

void ALTKeychainEmitEvent(NSString *item, ALTKeychainStatus status)
{
    const char *statusName = "unavailable";
    switch (status) {
        case ALTKeychainStatusFound:
            statusName = "found";
            break;
        case ALTKeychainStatusNotFound:
            statusName = "missing";
            break;
        case ALTKeychainStatusDenied:
            statusName = "denied";
            break;
        case ALTKeychainStatusUnavailable:
            statusName = "unavailable";
            break;
    }
    fprintf(stderr, "EVENT:keychain item=%s status=%s\n",
            (item.length > 0 ? item.UTF8String : "unknown"),
            statusName);
    fflush(stderr);
}
