//
//  anisette.mm
//  AltSign CLI
//
//  Anisette 数据获取 — 优先 AOSKit，fallback AuthKit
//  参照 AltStore AnisetteDataManager 实现
//

#import "anisette.h"
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>

static NSString *SysctlString(const char *name, NSString *fallback) {
    char value[256];
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) == 0 && value[0] != '\0') {
        return [NSString stringWithUTF8String:value];
    }
    return fallback;
}

static NSString *MachineModel(void) {
    return SysctlString("hw.model", @"MacBookPro18,3");
}

static NSString *MacOSProductVersion(void) {
    return SysctlString("kern.osproductversion", @"15.0");
}

static NSString *MacOSBuildVersion(void) {
    return SysctlString("kern.osversion", @"24F74");
}

static NSString *HeaderValue(NSDictionary *headers, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        id value = headers[key];
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
    }
    return nil;
}

static Class AOSUtilitiesClass(void) {
    NSBundle *aosKit = [NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AOSKit.framework"];
    if (aosKit && ![aosKit isLoaded]) {
        [aosKit load];
    }
    return NSClassFromString(@"AOSUtilities");
}

static NSString *MachineUDID(void) {
    Class utilities = AOSUtilitiesClass();
    SEL udidSel = NSSelectorFromString(@"machineUDID");
    if (utilities && [utilities respondsToSelector:udidSel]) {
        NSString *value = ((id (*)(id, SEL))objc_msgSend)(utilities, udidSel);
        if ([value isKindOfClass:NSString.class] && value.length > 0) return value;
    }
    return nil;
}

static NSString *MachineSerialNumber(void) {
    Class utilities = AOSUtilitiesClass();
    SEL serialSel = NSSelectorFromString(@"machineSerialNumber");
    if (utilities && [utilities respondsToSelector:serialSel]) {
        NSString *value = ((id (*)(id, SEL))objc_msgSend)(utilities, serialSel);
        if ([value isKindOfClass:NSString.class] && value.length > 0) return value;
    }
    return nil;
}

static NSString *DeviceDescription(NSString *deviceModel, NSString *osVersion, NSString *buildVersion) {
    return [NSString stringWithFormat:@"<%@> <macOS;%@;%@>",
            deviceModel, osVersion, buildVersion];
}

static NSString *Base64LocalUserID(NSString *udid) {
    if (!udid) return @"";
    return [[udid dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

@implementation ALTAnisetteData

- (instancetype)initWithMachineID:(NSString *)machineID
                  oneTimePassword:(NSString *)oneTimePassword
                      localUserID:(NSString *)localUserID
                      routingInfo:(NSUInteger)routingInfo
           deviceUniqueIdentifier:(NSString *)deviceUniqueIdentifier
               deviceSerialNumber:(NSString *)deviceSerialNumber
                deviceDescription:(NSString *)deviceDescription
                             date:(NSDate *)date
                           locale:(NSString *)locale
                         timeZone:(NSString *)timeZone
{
    self = [super init];
    if (self) {
        _machineID = [machineID copy];
        _oneTimePassword = [oneTimePassword copy];
        _localUserID = [localUserID copy];
        _routingInfo = routingInfo;
        _deviceUniqueIdentifier = [deviceUniqueIdentifier copy];
        _deviceSerialNumber = [deviceSerialNumber copy];
        _deviceDescription = [deviceDescription copy];
        _date = date;
        _locale = [locale copy];
        _timeZone = [timeZone copy];
    }
    return self;
}

+ (void)fetchAnisetteDataWithCompletion:(void (^)(ALTAnisetteData * _Nullable, NSError * _Nullable))completion
{
    // 主路径：AOSKit
    ALTAnisetteData * _Nullable (^fetchFromAOSKit)(void) = ^ALTAnisetteData * _Nullable {
        Class utilities = AOSUtilitiesClass();
        if (!utilities) {
            NSLog(@"[Anisette] AOSUtilities not found");
            return nil;
        }

        SEL otpSel = NSSelectorFromString(@"retrieveOTPHeadersForDSID:");
        if (![utilities respondsToSelector:otpSel]) {
            NSLog(@"[Anisette] AOSUtilities does not respond to retrieveOTPHeadersForDSID:");
            return nil;
        }

        NSDictionary *requestHeaders = ((id (*)(id, SEL, id))objc_msgSend)(
            utilities, otpSel, @"-2"
        );
        if (!requestHeaders || requestHeaders.count == 0) {
            NSLog(@"[Anisette] retrieveOTPHeadersForDSID returned empty");
            return nil;
        }
        NSString *headerKeys = [[requestHeaders.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","];
        NSString *machineID = HeaderValue(requestHeaders, @[@"X-Apple-I-MD-M", @"X-Apple-MD-M", @"X-Apple-I-MD-MachineId"]);
        NSString *oneTimePassword = HeaderValue(requestHeaders, @[@"X-Apple-I-MD", @"X-Apple-MD", @"X-Apple-I-MD-OTP"]);
        if (machineID.length == 0 || oneTimePassword.length == 0) {
            fprintf(stderr, "EVENT:anisette source=aoskit status=missing_otp keys=%s\n", headerKeys.UTF8String ?: "");
            fflush(stderr);
            return nil;
        }

        NSString *deviceID = MachineUDID() ?: @"Unknown";
        BOOL serialFromAOS = MachineSerialNumber() != nil;
        NSString *serialNumber = MachineSerialNumber() ?: @"C0FFFFFFFFFFFF";
        BOOL luFromAOS = HeaderValue(requestHeaders, @[@"X-Apple-I-MD-LU", @"X-Apple-MD-LU"]).length > 0;
        NSString *localUserID = HeaderValue(requestHeaders, @[@"X-Apple-I-MD-LU", @"X-Apple-MD-LU"]) ?: Base64LocalUserID(deviceID);
        NSString *rinfo = HeaderValue(requestHeaders, @[@"X-Apple-I-MD-RINFO", @"X-Apple-MD-RINFO"]);
        NSUInteger routingInfo = rinfo.length > 0 ? (NSUInteger)[rinfo longLongValue] : 84215040;

        NSString *deviceModel = MachineModel();
        NSString *osVersion = MacOSProductVersion();
        NSString *buildVersion = MacOSBuildVersion();
        NSString *deviceDescription = DeviceDescription(deviceModel, osVersion, buildVersion);

        fprintf(stderr,
            "EVENT:anisette source=aoskit status=ok keys=%s mid_bytes=%lu otp_bytes=%lu routing=%s serial=%s lu=%s os=%s build=%s desc=short\n",
            headerKeys.UTF8String ?: "",
            (unsigned long)machineID.length,
            (unsigned long)oneTimePassword.length,
            rinfo.length > 0 ? "aoskit" : "default",
            serialFromAOS ? "aoskit" : "fallback",
            luFromAOS ? "aoskit" : "derived",
            osVersion.UTF8String ?: "",
            buildVersion.UTF8String ?: "");
        fflush(stderr);

        return [[ALTAnisetteData alloc]
            initWithMachineID:machineID
              oneTimePassword:oneTimePassword
                  localUserID:localUserID
                  routingInfo:routingInfo
       deviceUniqueIdentifier:deviceID
           deviceSerialNumber:serialNumber
            deviceDescription:deviceDescription
                         date:[NSDate date]
                       locale:[[NSLocale currentLocale] localeIdentifier]
                     timeZone:[[NSTimeZone localTimeZone] abbreviation]];
    };

    ALTAnisetteData *data = fetchFromAOSKit();
    if (data) {
        completion(data, nil);
        return;
    }

    // Fallback：AuthKit AKAppleIDSession
    NSLog(@"[Anisette] Falling back to AuthKit...");

    static Class AKAppleIDSessionClass = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_LAZY);
        AKAppleIDSessionClass = NSClassFromString(@"AKAppleIDSession");
    });

    if (!AKAppleIDSessionClass) {
        completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-1
                                        userInfo:@{NSLocalizedDescriptionKey: @"AuthKit not available"}]);
        return;
    }

    @try {
        id session = ((id (*)(id, SEL, id))objc_msgSend)(
            [AKAppleIDSessionClass alloc],
            NSSelectorFromString(@"initWithIdentifier:"),
            @"com.apple.gs.xcode.auth"
        );

        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com"]];
        NSDictionary *headers = ((id (*)(id, SEL, id))objc_msgSend)(
            session, NSSelectorFromString(@"appleIDHeadersForRequest:"), request
        );

        if (!headers) {
            completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-2
                                            userInfo:@{NSLocalizedDescriptionKey: @"AuthKit returned empty headers"}]);
            return;
        }

        NSString *machineID = HeaderValue(headers, @[@"X-Apple-I-MD-M", @"X-Apple-MD-M", @"X-Apple-I-MD-MachineId"]) ?: @"";
        NSString *otp = HeaderValue(headers, @[@"X-Apple-I-MD", @"X-Apple-MD", @"X-Apple-I-MD-OTP"]) ?: @"";
        NSString *localUserID = HeaderValue(headers, @[@"X-Apple-I-MD-LU", @"X-Apple-MD-LU"]) ?: @"";
        NSString *rinfoStr = HeaderValue(headers, @[@"X-Apple-I-MD-RINFO", @"X-Apple-MD-RINFO"]);
        NSUInteger routingInfo = rinfoStr.length > 0 ? (NSUInteger)[rinfoStr longLongValue] : 0;
        NSString *deviceID = MachineUDID() ?: HeaderValue(headers, @[@"X-Mme-Device-Id", @"X-Apple-I-MD-LU"]) ?: @"";
        NSString *serialNumber = MachineSerialNumber() ?: HeaderValue(headers, @[@"X-Apple-I-SRL-NO"]) ?: @"";
        if (localUserID.length == 0 && deviceID.length > 0) {
            localUserID = Base64LocalUserID(deviceID);
        }

        fprintf(stderr,
            "EVENT:anisette source=authkit status=%s keys=%s mid_bytes=%lu otp_bytes=%lu routing=%s serial=%s\n",
            (machineID.length > 0 && otp.length > 0) ? "ok" : "missing_otp",
            [[[headers.allKeys sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","] UTF8String] ?: "",
            (unsigned long)machineID.length,
            (unsigned long)otp.length,
            rinfoStr.length > 0 ? "authkit" : "default",
            MachineSerialNumber() ? "aoskit" : "fallback");
        fflush(stderr);
        if (machineID.length == 0 || otp.length == 0) {
            completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-2
                                            userInfo:@{NSLocalizedDescriptionKey: @"AuthKit returned empty anisette headers"}]);
            return;
        }

        ALTAnisetteData *fallbackData = [[ALTAnisetteData alloc]
            initWithMachineID:machineID
              oneTimePassword:otp
                  localUserID:localUserID
                  routingInfo:routingInfo
       deviceUniqueIdentifier:deviceID
           deviceSerialNumber:serialNumber
            deviceDescription:DeviceDescription(MachineModel(), MacOSProductVersion(), MacOSBuildVersion())
                         date:[NSDate date]
                       locale:[[NSLocale currentLocale] localeIdentifier]
                     timeZone:[[NSTimeZone localTimeZone] abbreviation]];

        completion(fallbackData, nil);
    } @catch (NSException *exception) {
        completion(nil, [NSError errorWithDomain:@"com.altsign.anisette" code:-3
                                        userInfo:@{NSLocalizedDescriptionKey: exception.reason ?: @"AuthKit exception"}]);
    }
}

- (NSDictionary<NSString *, NSString *> *)httpHeaders
{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];

    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    headers[@"X-Apple-I-MD"]       = self.oneTimePassword ?: @"";
    headers[@"X-Apple-I-MD-M"]     = self.machineID ?: @"";
    headers[@"X-Apple-I-MD-LU"]    = self.localUserID ?: @"";
    headers[@"X-Apple-I-MD-RINFO"] = [NSString stringWithFormat:@"%lu", (unsigned long)self.routingInfo];
    headers[@"X-Mme-Device-Id"]    = self.deviceUniqueIdentifier ?: @"";
    headers[@"X-Apple-I-SRL-NO"]   = self.deviceSerialNumber ?: @"";
    headers[@"X-Apple-I-Client-Time"] = [formatter stringFromDate:self.date];
    headers[@"X-Apple-I-TimeZone"] = self.timeZone ?: @"UTC";
    headers[@"X-Apple-Locale"]     = self.locale ?: @"en_US";
    headers[@"X-MMe-Client-Info"]  = self.deviceDescription ?: @"";
    return headers;
}

@end
