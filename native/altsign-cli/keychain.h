//
//  keychain.h
//  AltSign CLI
//
//  Restricted login-keychain access for the session and certificate keys.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, ALTKeychainStatus) {
    ALTKeychainStatusFound = 0,
    ALTKeychainStatusNotFound,
    ALTKeychainStatusDenied,
    ALTKeychainStatusUnavailable,
};

FOUNDATION_EXPORT BOOL ALTKeychainAccessWasDenied(void);
FOUNDATION_EXPORT void ALTKeychainMarkAccessDenied(void);
FOUNDATION_EXPORT BOOL ALTKeychainOSStatusIsDenied(OSStatus status);
FOUNDATION_EXPORT ALTKeychainStatus ALTKeychainStatusFromOSStatus(OSStatus status);

FOUNDATION_EXPORT ALTKeychainStatus ALTKeychainLoadData(NSString *service,
                                                        NSString *account,
                                                        BOOL allowUI,
                                                        NSData *_Nullable *_Nullable outData);

FOUNDATION_EXPORT BOOL ALTKeychainSaveData(NSString *service,
                                           NSString *account,
                                           NSData *data,
                                           NSString *label);

FOUNDATION_EXPORT void ALTKeychainDeleteItems(NSString *service, NSString *_Nullable account);

FOUNDATION_EXPORT void ALTKeychainEmitEvent(NSString *item, ALTKeychainStatus status);

NS_ASSUME_NONNULL_END
