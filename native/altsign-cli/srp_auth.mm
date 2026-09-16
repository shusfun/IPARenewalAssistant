#import "srp_auth.h"
#import "keychain.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <CFNetwork/CFNetwork.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>

extern "C" {
#include <corecrypto/cc.h>
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccrng.h>
}

static NSString *const kGSAEndpoint = @"https://gsa.apple.com/grandslam/GsService2";
static NSString *const kGSA2FARequest = @"https://gsa.apple.com/auth/verify/trusteddevice";
static NSString *const kGSA2FAValidate = @"https://gsa.apple.com/grandslam/GsService2/validate";

static NSString *CFNetworkBundleVersion(void) {
    NSArray<NSString *> *plistPaths = @[
        @"/System/Library/Frameworks/CFNetwork.framework/Resources/Info.plist",
        @"/System/Library/Frameworks/CFNetwork.framework/Versions/A/Resources/Info.plist",
    ];
    for (NSString *path in plistPaths) {
        NSString *version = [[NSDictionary dictionaryWithContentsOfFile:path][@"CFBundleVersion"] description];
        if (version.length > 0) {
            return version;
        }
    }
    return @"3826.500.131";
}

static NSString *GSAUserAgent(void) {
    static NSString *value;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char release[64] = {0};
        size_t size = sizeof(release);
        NSString *cfNetwork = CFNetworkBundleVersion();
        if (sysctlbyname("kern.osrelease", release, &size, NULL, 0) != 0 || release[0] == '\0') {
            value = [NSString stringWithFormat:@"akd/1.0 CFNetwork/%@ Darwin/24.6.0", cfNetwork];
        } else {
            value = [NSString stringWithFormat:@"akd/1.0 CFNetwork/%@ Darwin/%s", cfNetwork, release];
        }
    });
    return value;
}

static NSString *GSAXcodeClientInfo(NSString *baseDescription) {
    NSString *base = [baseDescription stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (base.length == 0 || [base containsString:@"com.apple.AuthKit"]) {
        return base.length > 0 ? base : @"";
    }
    return [NSString stringWithFormat:@"%@ <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>", base];
}

static NSString *const kGSA2FAUserAgent = @"Xcode";
static NSString *const kGSAXcodeVersion = @"26.0 (17A324)";

static NSURLSession *ALTSharedSession(void) {
    static NSURLSession *session;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    });
    return session;
}

BOOL ALTVerboseLogging = NO;

static NSInteger const kAltSignErrorCodeGeneric = -1;
static NSInteger const kAltSignErrorCode2FARequired = -21600;
static NSInteger const kAltSignErrorCodeInvalid2FA = -21669;

static const char ALTHexCharacters[] = "0123456789abcdef";

static NSDateFormatter *GSAClientTimeFormatter(void) {
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
        formatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
    });
    return formatter;
}

static void ALTDigestUpdateString(const struct ccdigest_info *diInfo, struct ccdigest_ctx *diCtx, NSString *string) {
    ccdigest_update(diInfo, diCtx, string.length, string.UTF8String);
}

static void ALTDigestUpdateData(const struct ccdigest_info *diInfo, struct ccdigest_ctx *diCtx, NSData *data) {
    uint32_t dataLen = (uint32_t)data.length;
    ccdigest_update(diInfo, diCtx, sizeof(dataLen), &dataLen);
    ccdigest_update(diInfo, diCtx, dataLen, data.bytes);
}

static NSData * _Nullable ALTPBKDF2SRP(const struct ccdigest_info *diInfo, BOOL isS2K, NSString *password, NSData *salt, int iterations) {
    const struct ccdigest_info *passwordDiInfo = ccsha256_di();
    const char *passwordUTF8 = password.UTF8String;

    char *digestRaw = (char *)malloc(passwordDiInfo->output_size);
    ccdigest(passwordDiInfo, strlen(passwordUTF8), passwordUTF8, digestRaw);

    size_t finalDigestLen = passwordDiInfo->output_size * (isS2K ? 1 : 2);
    char *digest = (char *)malloc(finalDigestLen);

    if (isS2K) {
        memcpy(digest, digestRaw, finalDigestLen);
    } else {
        for (int i = 0; i < passwordDiInfo->output_size; i++) {
            char byte = digestRaw[i];
            digest[i * 2 + 0] = ALTHexCharacters[(byte >> 4) & 0x0F];
            digest[i * 2 + 1] = ALTHexCharacters[(byte >> 0) & 0x0F];
        }
    }

    NSMutableData *data = [NSMutableData dataWithLength:diInfo->output_size];
    int result = ccpbkdf2_hmac(diInfo,
                               finalDigestLen,
                               digest,
                               salt.length,
                               salt.bytes,
                               iterations,
                               diInfo->output_size,
                               data.mutableBytes);

    free(digestRaw);
    free(digest);

    if (result != 0) {
        return nil;
    }

    return data;
}

static NSData * _Nullable ALTCreateSessionKey(ccsrp_ctx_t srpCtx, const char *keyName) {
    size_t keyLen = 0;
    const void *sessionKey = ccsrp_get_session_key(srpCtx, &keyLen);
    if (sessionKey == NULL || keyLen == 0) {
        return nil;
    }

    const struct ccdigest_info *diInfo = ccsha256_di();
    size_t hmacLen = diInfo->output_size;
    unsigned char *hmacBytes = (unsigned char *)malloc(hmacLen);
    cchmac(diInfo, keyLen, sessionKey, strlen(keyName), keyName, hmacBytes);

    NSData *derivedKey = [NSData dataWithBytes:hmacBytes length:hmacLen];
    free(hmacBytes);
    return derivedKey;
}

static NSData * _Nullable ALTDecryptDataCBC(ccsrp_ctx_t srpCtx, NSData *spd) {
    NSData *extraDataKey = ALTCreateSessionKey(srpCtx, "extra data key:");
    NSData *extraDataIV = ALTCreateSessionKey(srpCtx, "extra data iv:");
    if (extraDataKey == nil || extraDataIV == nil) {
        return nil;
    }

    NSMutableData *decryptedData = [NSMutableData dataWithLength:spd.length];
    const struct ccmode_cbc *decryptMode = ccaes_cbc_decrypt_mode();

    cccbc_iv *iv = (cccbc_iv *)malloc(decryptMode->block_size);
    if (extraDataIV.bytes) {
        memcpy(iv, extraDataIV.bytes, decryptMode->block_size);
    } else {
        memset(iv, 0, decryptMode->block_size);
    }

    cccbc_ctx *ctxBuffer = (cccbc_ctx *)malloc(decryptMode->size);
    decryptMode->init(decryptMode, ctxBuffer, extraDataKey.length, extraDataKey.bytes);

    size_t length = ccpad_pkcs7_decrypt(decryptMode,
                                        ctxBuffer,
                                        iv,
                                        spd.length,
                                        spd.bytes,
                                        decryptedData.mutableBytes);

    free(iv);
    free(ctxBuffer);

    if (length > spd.length) {
        return nil;
    }

    decryptedData.length = length;
    return decryptedData;
}

static NSData * _Nullable ALTDecryptDataGCM(NSData *sk, NSData *encryptedData) {
    if (encryptedData.length < 35) {
        return nil;
    }

    if (cc_cmp_safe(3, encryptedData.bytes, "XYZ")) {
        return nil;
    }

    const struct ccmode_gcm *decryptMode = ccaes_gcm_decrypt_mode();
    ccgcm_ctx *gcmCtx = (ccgcm_ctx *)malloc(decryptMode->size);
    decryptMode->init(decryptMode, gcmCtx, sk.length, sk.bytes);

    decryptMode->set_iv(gcmCtx, 16, (const unsigned char *)encryptedData.bytes + 3);
    decryptMode->gmac(gcmCtx, 3, encryptedData.bytes);

    size_t decryptedLen = encryptedData.length - 35;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:decryptedLen];
    decryptMode->gcm(gcmCtx,
                     decryptedLen,
                     (const unsigned char *)encryptedData.bytes + 19,
                     decryptedData.mutableBytes);

    char tag[16];
    decryptMode->finalize(gcmCtx, 16, tag);
    free(gcmCtx);

    if (cc_cmp_safe(16, (const unsigned char *)encryptedData.bytes + decryptedLen + 19, tag)) {
        return nil;
    }

    return decryptedData;
}

static NSData *ALTCreateAppTokensChecksum(NSData *sk, NSString *adsid, NSArray<NSString *> *apps) {
    const struct ccdigest_info *diInfo = ccsha256_di();
    size_t hmacSize = cchmac_di_size(diInfo);
    struct cchmac_ctx *hmacCtx = (struct cchmac_ctx *)malloc(hmacSize);

    cchmac_init(diInfo, hmacCtx, sk.length, sk.bytes);

    const char *key = "apptokens";
    cchmac_update(diInfo, hmacCtx, strlen(key), key);

    const char *adsidUTF8 = adsid.UTF8String;
    cchmac_update(diInfo, hmacCtx, strlen(adsidUTF8), adsidUTF8);

    for (NSString *app in apps) {
        const char *appUTF8 = app.UTF8String ?: "";
        cchmac_update(diInfo, hmacCtx, strlen(appUTF8), appUTF8);
    }

    NSMutableData *checksum = [NSMutableData dataWithLength:diInfo->output_size];
    cchmac_final(diInfo, hmacCtx, (unsigned char *)checksum.mutableBytes);
    free(hmacCtx);

    return checksum;
}

static NSData * _Nullable PlistSerialize(NSDictionary *dict) {
    return [NSPropertyListSerialization dataWithPropertyList:dict
                                                      format:NSPropertyListXMLFormat_v1_0
                                                     options:0
                                                       error:nil];
}

static NSDictionary * _Nullable PlistDeserialize(NSData *data, NSError **error) {
    if (!data) {
        return nil;
    }
    return [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:error];
}

static NSError *SRPError(NSInteger code, NSString *description) {
    return [NSError errorWithDomain:@"com.altsign.srp"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description ?: @"SRP error"}];
}

static NSString *DictFieldSummary(NSDictionary *dict) {
    if (![dict isKindOfClass:[NSDictionary class]] || dict.count == 0) {
        return @"none";
    }
    NSArray *keys = [[dict allKeys] sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        return [[a description] compare:[b description]];
    }];
    NSMutableArray *parts = [NSMutableArray array];
    for (id key in keys) {
        id value = dict[key];
        NSUInteger size = 0;
        if ([value isKindOfClass:[NSData class]]) {
            size = [(NSData *)value length];
        } else if ([value isKindOfClass:[NSString class]]) {
            size = [(NSString *)value length];
        } else if ([value isKindOfClass:[NSDictionary class]] || [value isKindOfClass:[NSArray class]]) {
            size = [value count];
        }
        [parts addObject:[NSString stringWithFormat:@"%@:%s:%lu", [key description], class_getName([value class]), (unsigned long)size]];
    }
    return [parts componentsJoinedByString:@","];
}

static BOOL ExtractXcodeAuthTokenFromMap(id tokenMap, NSString *app,
                                         NSString **outToken, NSDate **outExpiry) {
    if (![tokenMap isKindOfClass:[NSDictionary class]] || app.length == 0) {
        return NO;
    }
    id entry = ((NSDictionary *)tokenMap)[app];
    if ([entry isKindOfClass:[NSString class]]) {
        NSString *token = (NSString *)entry;
        if (token.length == 0) {
            return NO;
        }
        if (outToken) {
            *outToken = token;
        }
        return YES;
    }
    if (![entry isKindOfClass:[NSDictionary class]]) {
        return NO;
    }
    NSDictionary *tokenDictionary = (NSDictionary *)entry;
    NSString *token = tokenDictionary[@"token"] ?: tokenDictionary[@"Token"] ?: tokenDictionary[@"at"] ?: tokenDictionary[@"pet"];
    if (token.length == 0) {
        return NO;
    }
    if (outToken) {
        *outToken = token;
    }
    NSNumber *expiryMS = tokenDictionary[@"expiry"];
    if (outExpiry && [expiryMS isKindOfClass:[NSNumber class]]) {
        *outExpiry = [NSDate dateWithTimeIntervalSince1970:(double)expiryMS.integerValue / 1000.0];
    }
    return YES;
}

static BOOL ExtractXcodeAuthToken(id encryptedToken, NSData *sessionKey, NSString *app,
                                  NSString **outToken, NSDate **outExpiry) {
    if (![encryptedToken isKindOfClass:[NSData class]] || !sessionKey || app.length == 0) {
        return NO;
    }
    NSData *decryptedToken = ALTDecryptDataGCM(sessionKey, encryptedToken);
    if (!decryptedToken) {
        return NO;
    }
    NSDictionary *tokenPlist = PlistDeserialize(decryptedToken, nil);
    NSDictionary *tokenDictionary = tokenPlist[@"t"][app];
    if (![tokenDictionary isKindOfClass:[NSDictionary class]]) {
        return NO;
    }
    NSString *token = tokenDictionary[@"token"];
    if (token.length == 0) {
        return NO;
    }
    if (outToken) {
        *outToken = token;
    }
    NSNumber *expiryMS = tokenDictionary[@"expiry"];
    if (outExpiry && [expiryMS isKindOfClass:[NSNumber class]]) {
        *outExpiry = [NSDate dateWithTimeIntervalSince1970:(double)expiryMS.integerValue / 1000.0];
    }
    return YES;
}

static void OverlayAnisetteOnCPD(NSMutableDictionary *cpd, ALTAnisetteData *anisette) {
    if (!cpd || !anisette) return;
    NSString *clientTime = [GSAClientTimeFormatter() stringFromDate:anisette.date ?: [NSDate date]];
    cpd[@"X-Apple-I-Client-Time"] = clientTime;
    cpd[@"X-Apple-I-MD"] = anisette.oneTimePassword ?: @"";
    cpd[@"X-Apple-I-MD-M"] = anisette.machineID ?: @"";
    cpd[@"X-Apple-I-MD-LU"] = anisette.localUserID ?: @"";
    cpd[@"X-Apple-I-MD-RINFO"] = @(anisette.routingInfo);
    cpd[@"X-Mme-Device-Id"] = anisette.deviceUniqueIdentifier ?: @"";
    cpd[@"X-Apple-I-SRL-NO"] = anisette.deviceSerialNumber ?: @"";
    cpd[@"X-MMe-Client-Info"] = anisette.deviceDescription ?: @"";
    if (anisette.locale.length > 0) {
        cpd[@"X-Apple-Locale"] = anisette.locale;
        cpd[@"loc"] = anisette.locale;
    }
    if (anisette.timeZone.length > 0) {
        cpd[@"X-Apple-I-TimeZone"] = anisette.timeZone;
    }
}

static NSString *GSAProxyLabel(void) {
    NSDictionary *explicitProxy = ALTSharedSession().configuration.connectionProxyDictionary;
    return explicitProxy.count > 0 ? @"session_override" : @"system_default";
}

static NSString *GSAContentKind(NSData *data, NSHTTPURLResponse *http) {
    if (data.length == 0) return @"empty";
    NSString *headerType = [[http allHeaderFields][@"Content-Type"] description] ?: @"";
    NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!raw) return @"binary";
    NSString *lower = raw.lowercaseString;
    if ([lower containsString:@"<html"] || [lower containsString:@"service temporarily unavailable"]) return @"html";
    if ([raw containsString:@"<plist"] || [raw hasPrefix:@"bplist"] || [headerType.lowercaseString containsString:@"plist"]) return @"plist";
    if ([headerType.lowercaseString containsString:@"xml"] || [raw hasPrefix:@"<?xml"]) return @"xml";
    return @"text";
}

static void LogGSAEvent(NSString *stage, NSString *method, NSInteger status, NSTimeInterval duration, NSString *content, NSString *transportError) {
    NSMutableString *line = [NSMutableString stringWithFormat:
        @"EVENT:gsa stage=%@ method=%@ status=%ld duration_ms=%ld content=%@ proxy=%@",
        stage ?: @"unknown",
        method ?: @"POST",
        (long)status,
        (long)(duration * 1000.0),
        content ?: @"unknown",
        GSAProxyLabel()];
    if (transportError.length > 0) {
        [line appendFormat:@" transport=%@", transportError];
    }
    fprintf(stderr, "%s\n", line.UTF8String);
    fflush(stderr);
}

static void ApplyGSAHeaders(NSMutableURLRequest *request, ALTAnisetteData *anisetteData, NSDictionary *extraHeaders) {
    [request setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Accept"];
    [request setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:GSAUserAgent() forHTTPHeaderField:@"User-Agent"];
    [request setValue:@"com.apple.gs.xcode.auth" forHTTPHeaderField:@"X-Apple-App-Info"];
    [request setValue:kGSAXcodeVersion forHTTPHeaderField:@"X-Xcode-Version"];
    NSDictionary<NSString *, NSString *> *anisetteHeaders = [anisetteData httpHeaders];
    for (NSString *key in anisetteHeaders) {
        [request setValue:anisetteHeaders[key] forHTTPHeaderField:key];
    }
    for (NSString *key in extraHeaders) {
        [request setValue:extraHeaders[key] forHTTPHeaderField:key];
    }
}

static void SendGSARequest(NSString *stage,
                           NSDictionary * _Nullable requestDict,
                           ALTAnisetteData *anisetteData,
                           NSDictionary * _Nullable extraHeaders,
                           void (^completion)(NSDictionary * _Nullable response, NSError * _Nullable error))
{
    NSData *bodyData = nil;
    if (requestDict) {
        bodyData = PlistSerialize(@{
            @"Header": @{@"Version": @"1.0.1"},
            @"Request": requestDict
        });
        if (!bodyData) {
            completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to serialize plist request"));
            return;
        }
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSAEndpoint]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;
    ApplyGSAHeaders(request, anisetteData, extraHeaders);

    NSDate *started = [NSDate date];
    NSURLSessionDataTask *task = [ALTSharedSession()
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSTimeInterval duration = [[NSDate date] timeIntervalSinceDate:started];
        NSHTTPURLResponse *http = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        NSInteger httpStatus = http ? http.statusCode : 0;
        NSString *content = error ? @"transport" : GSAContentKind(data, http);
        fprintf(stderr, "EVENT:gsa stage=%s body_bytes=%lu\n", stage.UTF8String ?: "unknown", (unsigned long)bodyData.length);
        fflush(stderr);
        LogGSAEvent(stage, @"POST", httpStatus, duration, content, error.localizedFailureReason ?: (error ? @"failed" : nil));

        if (error) {
            completion(nil, error);
            return;
        }
        if (httpStatus >= 500) {
            completion(nil, SRPError((NSInteger)httpStatus, [NSString stringWithFormat:@"HTTP %ld from Apple", (long)httpStatus]));
            return;
        }

        NSError *parseError = nil;
        NSDictionary *responseDict = PlistDeserialize(data, &parseError);
        if (!responseDict) {
            completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid plist response"));
            return;
        }

        NSDictionary *dictionary = responseDict[@"Response"];
        if (![dictionary isKindOfClass:[NSDictionary class]]) {
            completion(nil, SRPError(kAltSignErrorCodeGeneric, @"Missing Response in plist"));
            return;
        }

        NSDictionary *status = dictionary[@"Status"];
        NSInteger hsc = [status[@"hsc"] integerValue];
        NSInteger errorCode = [status[@"ec"] integerValue];
        if (errorCode != 0 || hsc >= 500) {
            NSString *errorDescription = status[@"em"] ?: [NSString stringWithFormat:@"GSA error (hsc=%ld, ec=%ld)", (long)hsc, (long)errorCode];
            fprintf(stderr, "EVENT:gsa stage=%s gsa_ec=%ld gsa_hsc=%ld\n", stage.UTF8String, (long)errorCode, (long)hsc);
            fflush(stderr);
            completion(nil, SRPError(errorCode ?: hsc, errorDescription));
            return;
        }

        completion(dictionary, nil);
    }];

    [task resume];
}

static NSString *const kSessionKeychainService = @"com.shus.iparenewalassistant.apple-session";
static NSString *const kSessionKeychainAccount = @"default";
static NSString *const kSessionKeychainLabel = @"IPARenewalAssistant Apple Session";

@implementation ALTAppleAPISession

- (instancetype)initWithDSID:(NSString *)dsid
                   authToken:(NSString *)authToken
                anisetteData:(ALTAnisetteData *)anisetteData
{
    self = [super init];
    if (self) {
        _dsid = [dsid copy];
        _authToken = [authToken copy];
        _anisetteData = anisetteData;
    }
    return self;
}

- (BOOL)saveForAppleID:(NSString *)appleID {
    if (appleID.length == 0 || self.dsid.length == 0 ||
        self.authToken.length == 0 || self.anisetteData == nil) {
        return NO;
    }

    NSMutableDictionary *session = [NSMutableDictionary dictionary];
    session[@"appleID"] = appleID;
    session[@"dsid"] = self.dsid;
    session[@"authToken"] = self.authToken;
    if (self.expirationDate) {
        session[@"expirationDate"] = self.expirationDate;
    }

    NSMutableDictionary *anisette = [NSMutableDictionary dictionary];
    anisette[@"machineID"] = self.anisetteData.machineID ?: @"";
    anisette[@"oneTimePassword"] = self.anisetteData.oneTimePassword ?: @"";
    anisette[@"localUserID"] = self.anisetteData.localUserID ?: @"";
    anisette[@"routingInfo"] = @(self.anisetteData.routingInfo);
    anisette[@"deviceUniqueIdentifier"] = self.anisetteData.deviceUniqueIdentifier ?: @"";
    anisette[@"deviceSerialNumber"] = self.anisetteData.deviceSerialNumber ?: @"";
    anisette[@"deviceDescription"] = self.anisetteData.deviceDescription ?: @"";
    anisette[@"date"] = self.anisetteData.date ?: [NSDate date];
    anisette[@"locale"] = self.anisetteData.locale ?: @"";
    anisette[@"timeZone"] = self.anisetteData.timeZone ?: @"";
    session[@"anisetteData"] = anisette;

    NSError *serializationError = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:session format:NSPropertyListBinaryFormat_v1_0 options:0 error:&serializationError];
    if (!data) return NO;
    return ALTKeychainSaveData(kSessionKeychainService, kSessionKeychainAccount, data, kSessionKeychainLabel);
}

+ (nullable instancetype)loadSession:(NSString *_Nullable *_Nullable)outAppleID {
    return [self loadSession:outAppleID allowUI:YES];
}

+ (nullable instancetype)loadSession:(NSString *_Nullable *_Nullable)outAppleID allowUI:(BOOL)allowUI {
    NSData *data = nil;
    ALTKeychainStatus status = ALTKeychainLoadData(kSessionKeychainService, kSessionKeychainAccount, allowUI, &data);
    if (status != ALTKeychainStatusFound || data.length == 0) return nil;
    NSDictionary *session = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:nil error:nil];
    if (![session isKindOfClass:NSDictionary.class]) return nil;
    NSString *appleID = [session[@"appleID"] isKindOfClass:NSString.class]
        ? session[@"appleID"]
        : nil;
    if (appleID.length == 0) return nil;
    ALTAppleAPISession *loadedSession = [self sessionFromDict:session];
    if (loadedSession != nil && outAppleID != NULL) {
        *outAppleID = appleID;
    }
    return loadedSession;
}

+ (nullable instancetype)sessionFromDict:(NSDictionary *)dict {
    NSDictionary *ad = dict[@"anisetteData"];
    id expirationDate = dict[@"expirationDate"];
    if (![dict[@"dsid"] isKindOfClass:NSString.class] ||
        [dict[@"dsid"] length] == 0 ||
        ![dict[@"authToken"] isKindOfClass:NSString.class] ||
        [dict[@"authToken"] length] == 0 ||
        ![ad isKindOfClass:NSDictionary.class] ||
        (expirationDate != nil &&
         ![expirationDate isKindOfClass:NSDate.class])) {
        return nil;
    }
    for (NSString *key in @[
        @"machineID", @"oneTimePassword", @"localUserID",
        @"deviceUniqueIdentifier", @"deviceSerialNumber",
        @"deviceDescription", @"locale", @"timeZone"
    ]) {
        id value = ad[key];
        if (value != nil && ![value isKindOfClass:NSString.class]) {
            return nil;
        }
    }
    if ((ad[@"routingInfo"] != nil &&
         ![ad[@"routingInfo"] isKindOfClass:NSNumber.class]) ||
        (ad[@"date"] != nil &&
         ![ad[@"date"] isKindOfClass:NSDate.class])) {
        return nil;
    }
    ALTAnisetteData *anisette = [[ALTAnisetteData alloc]
        initWithMachineID:ad[@"machineID"] ?: @""
          oneTimePassword:ad[@"oneTimePassword"] ?: @""
              localUserID:ad[@"localUserID"] ?: @""
              routingInfo:[ad[@"routingInfo"] integerValue]
   deviceUniqueIdentifier:ad[@"deviceUniqueIdentifier"] ?: @""
       deviceSerialNumber:ad[@"deviceSerialNumber"] ?: @""
        deviceDescription:ad[@"deviceDescription"] ?: @""
                     date:ad[@"date"] ?: [NSDate date]
                   locale:ad[@"locale"] ?: @""
                 timeZone:ad[@"timeZone"] ?: @""];

    ALTAppleAPISession *session = [[ALTAppleAPISession alloc]
        initWithDSID:dict[@"dsid"] ?: @""
           authToken:dict[@"authToken"] ?: @""
        anisetteData:anisette];
    session.expirationDate = expirationDate;
    return session;
}

+ (void)deleteSession {
    ALTKeychainDeleteItems(kSessionKeychainService, kSessionKeychainAccount);
}

- (BOOL)isExpired {
    if (!self.expirationDate) return YES;
    NSDate *buffer = [self.expirationDate dateByAddingTimeInterval:-300];
    return [buffer compare:[NSDate date]] == NSOrderedAscending;
}

@end

@implementation ALTAccount
@end

@interface ALTSRPContext : NSObject
@property (nonatomic, assign) struct ccsrp_ctx *srpCtx;
@property (nonatomic, assign) struct ccdigest_ctx *diCtx;
@end

@implementation ALTSRPContext
- (void)dealloc {
    if (_srpCtx) { free(_srpCtx); _srpCtx = NULL; }
    if (_diCtx) { free(_diCtx); _diCtx = NULL; }
}
@end

@interface ALTSRPAuthenticator ()
+ (void)fetchXcodeAuthTokenWithAdsid:(NSString *)adsid
                           idmsToken:(NSString *)idmsToken
                          sessionKey:(NSData *)sessionKey
                            requestC:(id)requestC
                                 cpd:(NSDictionary *)cpd
                        anisetteData:(ALTAnisetteData *)anisetteData
                    existingTokenMap:(id)existingTokenMap
              existingEncryptedToken:(id)existingEncryptedToken
                   completionHandler:(void (^)(NSString * _Nullable authToken,
                                               NSDate * _Nullable expirationDate,
                                               NSError * _Nullable error))completion;
@end

@implementation ALTSRPAuthenticator

+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completion
{
    [self authenticateWithAppleID:appleID password:password anisetteData:anisetteData
              verificationHandler:nil completionHandler:completion];
}

+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              verificationHandler:(nullable ALTVerificationHandler)verificationHandler
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completion
{
    NSLog(@"[SRP] Starting authentication");

    NSString *clientTime = [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]];
    NSString *locale = [NSLocale currentLocale].localeIdentifier ?: anisetteData.locale ?: @"en_US";
    NSString *timeZone = [NSTimeZone localTimeZone].abbreviation ?: anisetteData.timeZone ?: @"UTC";

    NSMutableDictionary *clientDictionary = [@{
        @"bootstrap": @YES,
        @"icscrec": @YES,
        @"loc": locale,
        @"pbe": @NO,
        @"prkgen": @YES,
        @"svct": @"iCloud",
        @"X-Apple-I-Client-Time": clientTime,
        @"X-Apple-Locale": locale,
        @"X-Apple-I-TimeZone": timeZone,
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD-RINFO": @(anisetteData.routingInfo),
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber ?: @"",
        @"X-MMe-Client-Info": anisetteData.deviceDescription ?: @"",
    } mutableCopy];
    fprintf(stderr, "EVENT:gsa stage=identity darwin=%s cfnetwork=%s client_info=short\n",
            [[[GSAUserAgent() componentsSeparatedByString:@"Darwin/"] lastObject] UTF8String] ?: "unknown",
            CFNetworkBundleVersion().UTF8String ?: "unknown");
    fflush(stderr);

    ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
    const struct ccdigest_info *diInfo = ccsha256_di();

    ALTSRPContext *ctx = [[ALTSRPContext alloc] init];
    ctx.diCtx = (struct ccdigest_ctx *)malloc(ccdigest_di_size(diInfo));
    ccdigest_init(diInfo, ctx.diCtx);

    ctx.srpCtx = (struct ccsrp_ctx *)malloc(ccsrp_sizeof_srp(diInfo, gp));
    ccsrp_ctx_init(ctx.srpCtx, diInfo, gp);
    ccsrp_client_set_noUsernameInX(ctx.srpCtx, true);
    SRP_RNG(ctx.srpCtx) = ccrng(NULL);

    __block ALTSRPContext *srpContext = ctx;

    NSArray<NSString *> *ps = @[@"s2k", @"s2k_fo"];
    ALTDigestUpdateString(diInfo, srpContext.diCtx, ps[0]);
    ALTDigestUpdateString(diInfo, srpContext.diCtx, @",");
    ALTDigestUpdateString(diInfo, srpContext.diCtx, ps[1]);

    size_t ASize = ccsrp_exchange_size(srpContext.srpCtx);
    char *ABytes = (char *)malloc(ASize);
    int startResult = ccsrp_client_start_authentication(srpContext.srpCtx, ccrng(NULL), ABytes);
    if (startResult != 0) {
        free(ABytes);
        completion(nil, nil, SRPError(startResult, @"Failed to start SRP authentication"));
        return;
    }

    NSData *AData = [NSData dataWithBytes:ABytes length:ASize];
    free(ABytes);

    ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");

    NSDictionary *initRequest = @{
        @"A2k": AData,
        @"ps": ps,
        @"cpd": clientDictionary,
        @"u": appleID,
        @"o": @"init"
    };

    SendGSARequest(@"init", initRequest, anisetteData, nil, ^(NSDictionary *initResponse, NSError *error) {
        if (error || !initResponse) {
            completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty init response"));
            return;
        }

        NSString *sp = initResponse[@"sp"];
        BOOL isS2K = [sp isEqualToString:@"s2k"];

        ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
        if (sp) {
            ALTDigestUpdateString(diInfo, srpContext.diCtx, sp);
        }

        id cValue = initResponse[@"c"];
        NSData *salt = initResponse[@"s"];
        NSNumber *iterations = initResponse[@"i"];
        NSData *BData = initResponse[@"B"];

        if (!cValue || !salt || !iterations || !BData) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid init challenge"));
            return;
        }

        NSData *passwordKey = ALTPBKDF2SRP(diInfo, isS2K, password, salt, iterations.intValue);
        if (!passwordKey) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to derive SRP password key"));
            return;
        }

        size_t MSize = ccsrp_session_size(srpContext.srpCtx);
        NSMutableData *MData = [NSMutableData dataWithLength:MSize];

        int challengeResult = ccsrp_client_process_challenge(srpContext.srpCtx,
                                                             appleID.UTF8String,
                                                             passwordKey.length,
                                                             passwordKey.bytes,
                                                             salt.length,
                                                             salt.bytes,
                                                             BData.bytes,
                                                             MData.mutableBytes);
        if (challengeResult != 0) {
            completion(nil, nil, SRPError(challengeResult, @"SRP challenge failed"));
            return;
        }

        NSDictionary *completeRequest = @{
            @"c": cValue,
            @"M1": MData,
            @"cpd": clientDictionary,
            @"u": appleID,
            @"o": @"complete"
        };

        SendGSARequest(@"complete", completeRequest, anisetteData, nil, ^(NSDictionary *completeResponse, NSError *error) {
            if (error || !completeResponse) {
                completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty complete response"));
                return;
            }

            NSData *M2Data = completeResponse[@"M2"];
            if (!M2Data || !ccsrp_client_verify_session(srpContext.srpCtx, (const uint8_t *)M2Data.bytes)) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to verify SRP session"));
                return;
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *spd = completeResponse[@"spd"];
            if (spd) {
                ALTDigestUpdateData(diInfo, srpContext.diCtx, spd);
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *sc = completeResponse[@"sc"];
            if (sc) {
                ALTDigestUpdateData(diInfo, srpContext.diCtx, sc);
            }

            ALTDigestUpdateString(diInfo, srpContext.diCtx, @"|");
            NSData *np = completeResponse[@"np"];
            if (!np) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing negotiation proof"));
                return;
            }

            size_t digestLen = diInfo->output_size;
            if (np.length != digestLen) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid negotiation proof length"));
                return;
            }

            unsigned char *digest = (unsigned char *)malloc(digestLen);
            diInfo->final(diInfo, srpContext.diCtx, digest);

            NSData *hmacKey = ALTCreateSessionKey(srpContext.srpCtx, "HMAC key:");
            if (!hmacKey) {
                free(digest);
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing SRP session key"));
                return;
            }

            unsigned char *hmacOut = (unsigned char *)malloc(digestLen);
            cchmac(diInfo, hmacKey.length, hmacKey.bytes, digestLen, digest, hmacOut);
            int proofMismatch = cc_cmp_safe(digestLen, hmacOut, np.bytes);
            free(digest);
            free(hmacOut);

            if (proofMismatch) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Invalid negotiation proof"));
                return;
            }

            NSData *decryptedData = ALTDecryptDataCBC(srpContext.srpCtx, spd);
            if (!decryptedData) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Failed to decrypt SRP payload"));
                return;
            }

            NSError *parseError = nil;
            NSDictionary *decryptedDictionary = PlistDeserialize(decryptedData, &parseError);
            if (!decryptedDictionary) {
                completion(nil, nil, parseError ?: SRPError(kAltSignErrorCodeGeneric, @"Failed to parse SRP payload"));
                return;
            }

            NSString *adsid = decryptedDictionary[@"adsid"];
            NSString *idmsToken = decryptedDictionary[@"GsIdmsToken"];
            if (adsid.length == 0 || idmsToken.length == 0) {
                completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing adsid or idmsToken"));
                return;
            }

            NSDictionary *statusDictionary = completeResponse[@"Status"];
            NSString *authType = statusDictionary[@"au"];
            fprintf(stderr, "EVENT:gsa stage=complete-au au=%s\n", authType.length ? authType.UTF8String : "none");
            fprintf(stderr, "EVENT:gsa stage=complete-keys fields=%s\n", DictFieldSummary(completeResponse).UTF8String);
            fprintf(stderr, "EVENT:gsa stage=spd-keys fields=%s\n", DictFieldSummary(decryptedDictionary).UTF8String);
            fflush(stderr);
            void (^finishWithToken)(NSString *, NSDate *, NSError *) = ^(NSString *authToken, NSDate *expirationDate, NSError *tokenError) {
                if (tokenError || authToken.length == 0) {
                    completion(nil, nil, tokenError ?: SRPError(kAltSignErrorCodeGeneric, @"Empty auth token"));
                    return;
                }
                ALTAccount *account = [[ALTAccount alloc] init];
                account.appleID = appleID;
                account.identifier = adsid;
                ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:adsid
                                                                            authToken:authToken
                                                                         anisetteData:anisetteData];
                session.expirationDate = expirationDate;
                if (![session saveForAppleID:appleID]) {
                    completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Could not persist the authenticated account"));
                    return;
                }
                NSLog(@"[SRP] Authentication successful, session saved (expires: %@)", expirationDate);
                completion(account, session, nil);
            };

            void (^runAppToken)(void) = ^{
                NSData *sk = decryptedDictionary[@"sk"];
                id requestC = completeResponse[@"c"] ?: decryptedDictionary[@"c"];
                if (!sk || !requestC) {
                    completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing app token key material"));
                    return;
                }
                [self fetchXcodeAuthTokenWithAdsid:adsid
                                         idmsToken:idmsToken
                                        sessionKey:sk
                                          requestC:requestC
                                               cpd:clientDictionary
                                      anisetteData:anisetteData
                                  existingTokenMap:decryptedDictionary[@"t"]
                            existingEncryptedToken:completeResponse[@"et"]
                                 completionHandler:finishWithToken];
            };

            void (^runTwoFactor)(void) = ^{
                [self _requestTwoFactorCodeForDSID:adsid idmsToken:idmsToken anisetteData:anisetteData
                                 completionHandler:^(NSError * _Nullable requestError) {
                    if (requestError) {
                        fprintf(stderr, "EVENT:gsa stage=2fa-request status=failed fallback=no\n");
                        fflush(stderr);
                        completion(nil, nil, requestError);
                        return;
                    }
                    fprintf(stderr, "EVENT:gsa stage=2fa-request status=ok\n");
                    fflush(stderr);
                    if (!verificationHandler) {
                        completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"Two-factor authentication required."));
                        return;
                    }
                    verificationHandler(^(NSString * _Nullable code) {
                        if (!code || code.length == 0) {
                            completion(nil, nil, SRPError(kAltSignErrorCode2FARequired, @"2FA code not provided"));
                            return;
                        }
                        [self submitTwoFactorCode:code dsid:adsid idmsToken:idmsToken anisetteData:anisetteData
                                completionHandler:^(BOOL success, NSError * _Nullable verifyError) {
                            if (!success) {
                                completion(nil, nil, verifyError ?: SRPError(kAltSignErrorCodeInvalid2FA, @"Incorrect verification code"));
                                return;
                            }
                            fprintf(stderr, "EVENT:gsa stage=2fa-validate status=ok\n");
                            fflush(stderr);
                            runAppToken();
                        }];
                    }, ^(void (^resendCompletion)(NSError * _Nullable error)) {
                        [self _requestTwoFactorCodeForDSID:adsid
                                                 idmsToken:idmsToken
                                              anisetteData:anisetteData
                                         completionHandler:resendCompletion];
                    });
                }];
            };

            BOOL appleRequested2FA = [authType isEqualToString:@"trustedDeviceSecondaryAuth"] ||
                                     [authType isEqualToString:@"secondaryAuth"];
            if (!appleRequested2FA) {
                fprintf(stderr, "EVENT:gsa stage=2fa-force au=%s\n", authType.length ? authType.UTF8String : "none");
                fflush(stderr);
            }
            runTwoFactor();
        });
    });
}

+ (void)_requestTwoFactorCodeForDSID:(NSString *)dsid
                           idmsToken:(NSString *)idmsToken
                        anisetteData:(ALTAnisetteData *)anisetteData
                   completionHandler:(void (^)(NSError * _Nullable error))completion
{
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, idmsToken];
    NSData *tokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Token = [tokenData base64EncodedStringWithOptions:0];

    NSDictionary<NSString *, NSString *> *headers = @{
        @"Content-Type": @"text/x-xml-plist",
        @"Accept": @"text/x-xml-plist",
        @"User-Agent": kGSA2FAUserAgent,
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": kGSAXcodeVersion,
        @"X-Apple-Identity-Token": base64Token,
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": GSAXcodeClientInfo(anisetteData.deviceDescription),
        @"X-Apple-I-Client-Time": [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": anisetteData.locale ?: [NSLocale currentLocale].localeIdentifier ?: @"en_US",
        @"X-Apple-I-TimeZone": anisetteData.timeZone ?: [NSTimeZone localTimeZone].abbreviation ?: @"UTC",
    };

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSA2FARequest]];
    request.HTTPMethod = @"GET";
    for (NSString *key in headers) {
        [request setValue:headers[key] forHTTPHeaderField:key];
    }

    NSLog(@"[2FA] Requesting trusted device code");
    NSURLSessionDataTask *task = [ALTSharedSession()
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            NSLog(@"[2FA] Request failed: %@", error);
            completion(error);
            return;
        }
        NSInteger httpStatus = 0;
        if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            httpStatus = ((NSHTTPURLResponse *)response).statusCode;
        }
        NSString *bodyPreview = @"";
        if (data.length > 0) {
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (raw) {
                bodyPreview = (ALTVerboseLogging || raw.length <= 200) ? raw : [raw substringToIndex:200];
            } else {
                bodyPreview = [NSString stringWithFormat:@"(binary, %lu bytes)", (unsigned long)data.length];
            }
        }
        NSString *content = GSAContentKind(data, [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil);
        fprintf(stderr, "EVENT:gsa stage=2fa-request status=%ld content=%s\n", (long)httpStatus, content.UTF8String ?: "unknown");
        fflush(stderr);
        if (ALTVerboseLogging) {
            NSLog(@"[2FA] Trusted device request HTTP %ld, bodyPreview: %@", (long)httpStatus, bodyPreview);
        } else {
            NSLog(@"[2FA] Trusted device request HTTP %ld", (long)httpStatus);
        }
        if (httpStatus < 200 || httpStatus >= 300) {
            completion(SRPError(httpStatus, [NSString stringWithFormat:@"HTTP %ld from 2FA request", (long)httpStatus]));
            return;
        }
        completion(nil);
    }];

    [task resume];
}

+ (void)fetchXcodeAuthTokenWithAdsid:(NSString *)adsid
                           idmsToken:(NSString *)idmsToken
                          sessionKey:(NSData *)sessionKey
                            requestC:(id)requestC
                                 cpd:(NSDictionary *)cpd
                        anisetteData:(ALTAnisetteData *)anisetteData
                    existingTokenMap:(id)existingTokenMap
              existingEncryptedToken:(id)existingEncryptedToken
                   completionHandler:(void (^)(NSString * _Nullable authToken,
                                               NSDate * _Nullable expirationDate,
                                               NSError * _Nullable error))completion
{
    NSArray<NSString *> *apps = @[@"com.apple.gs.xcode.auth"];
    if ([existingTokenMap isKindOfClass:[NSDictionary class]]) {
        NSDictionary *tokenMap = (NSDictionary *)existingTokenMap;
        NSArray *appKeys = [tokenMap.allKeys sortedArrayUsingSelector:@selector(compare:)];
        fprintf(stderr, "EVENT:gsa stage=spd-token-apps count=%lu apps=%s\n",
                (unsigned long)appKeys.count,
                [[appKeys componentsJoinedByString:@","] UTF8String] ?: "");
        id sample = tokenMap[appKeys.firstObject];
        fprintf(stderr, "EVENT:gsa stage=spd-token-shape class=%s fields=%s\n",
                sample ? class_getName([sample class]) : "nil",
                [sample isKindOfClass:[NSDictionary class]] ? DictFieldSummary(sample).UTF8String : "scalar");
        fflush(stderr);
    }
    NSString *existingToken = nil;
    NSDate *existingExpiry = nil;
    NSArray<NSString *> *tokenApps = @[
        @"com.apple.gs.xcode.auth"
    ];
    for (NSString *app in tokenApps) {
        if (ExtractXcodeAuthTokenFromMap(existingTokenMap, app, &existingToken, &existingExpiry)) {
            fprintf(stderr, "EVENT:gsa stage=complete-et used=spd-t app=%s\n", app.UTF8String);
            fflush(stderr);
            completion(existingToken, existingExpiry, nil);
            return;
        }
    }
    if (ExtractXcodeAuthToken(existingEncryptedToken, sessionKey, apps.firstObject, &existingToken, &existingExpiry)) {
        fprintf(stderr, "EVENT:gsa stage=complete-et used=yes\n");
        fflush(stderr);
        completion(existingToken, existingExpiry, nil);
        return;
    }
    fprintf(stderr, "EVENT:gsa stage=complete-et used=no\n");
    fflush(stderr);

    NSData *checksum = ALTCreateAppTokensChecksum(sessionKey, adsid, apps);
    NSMutableDictionary *appTokenRequest = [@{
        @"u": adsid,
        @"app": apps,
        @"t": idmsToken,
        @"checksum": checksum,
        @"cpd": cpd ?: @{},
        @"o": @"apptokens"
    } mutableCopy];
    if (requestC) {
        appTokenRequest[@"c"] = requestC;
    }
    NSUInteger cBytes = 0;
    if ([requestC isKindOfClass:[NSData class]]) {
        cBytes = [(NSData *)requestC length];
    } else if ([requestC isKindOfClass:[NSString class]]) {
        cBytes = [(NSString *)requestC lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    }
    fprintf(stderr, "EVENT:gsa stage=apptokens-prep c_class=%s c_bytes=%lu checksum_bytes=%lu anisette=reused client_info=session\n",
            requestC ? class_getName([requestC class]) : "nil",
            (unsigned long)cBytes,
            (unsigned long)checksum.length);
    fflush(stderr);

    SendGSARequest(@"apptokens", appTokenRequest, anisetteData, nil, ^(NSDictionary *response, NSError *error) {
        if (error || !response) {
            completion(nil, nil, error ?: SRPError(kAltSignErrorCodeGeneric, @"Empty app token response"));
            return;
        }

        NSString *token = nil;
        NSDate *expirationDate = nil;
        if (!ExtractXcodeAuthToken(response[@"et"], sessionKey, apps.firstObject, &token, &expirationDate)) {
            completion(nil, nil, SRPError(kAltSignErrorCodeGeneric, @"Missing Xcode auth token"));
            return;
        }
        completion(token, expirationDate, nil);
    });
}

+ (void)submitTwoFactorCode:(NSString *)code
                       dsid:(NSString *)dsid
                  idmsToken:(NSString *)idmsToken
               anisetteData:(ALTAnisetteData *)anisetteData
          completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion
{
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, idmsToken];
    NSData *tokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64Token = [tokenData base64EncodedStringWithOptions:0];

    NSDictionary<NSString *, NSString *> *headers = @{
        @"Content-Type": @"text/x-xml-plist",
        @"Accept": @"text/x-xml-plist",
        @"User-Agent": kGSA2FAUserAgent,
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": kGSAXcodeVersion,
        @"X-Apple-Identity-Token": base64Token,
        @"X-Apple-I-MD-M": anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": GSAXcodeClientInfo(anisetteData.deviceDescription),
        @"X-Apple-I-Client-Time": [GSAClientTimeFormatter() stringFromDate:anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": anisetteData.locale ?: [NSLocale currentLocale].localeIdentifier ?: @"en_US",
        @"X-Apple-I-TimeZone": anisetteData.timeZone ?: [NSTimeZone localTimeZone].abbreviation ?: @"UTC",
        @"security-code": code ?: @"",
    };

    NSMutableURLRequest *validateRequest = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kGSA2FAValidate]];
    validateRequest.HTTPMethod = @"GET";
    for (NSString *key in headers) {
        [validateRequest setValue:headers[key] forHTTPHeaderField:key];
    }

    NSLog(@"[2FA] Validating verification code");
    NSURLSessionDataTask *validateTask = [ALTSharedSession()
        dataTaskWithRequest:validateRequest
          completionHandler:^(NSData *validateData, NSURLResponse *validateResponse, NSError *validateError) {
        if (validateError) {
            NSLog(@"[2FA] Validate network error: %@", validateError);
            completion(NO, validateError);
            return;
        }

        NSInteger httpStatus = [(NSHTTPURLResponse *)validateResponse statusCode];
        NSLog(@"[2FA] Validate HTTP status: %ld", (long)httpStatus);

        if (!validateData || validateData.length == 0) {
            if (httpStatus >= 200 && httpStatus < 300) {
                NSLog(@"[2FA] Validation successful (empty body, HTTP %ld)", (long)httpStatus);
                completion(YES, nil);
            } else {
                completion(NO, SRPError(kAltSignErrorCodeGeneric, [NSString stringWithFormat:@"2FA validation failed (HTTP %ld, empty body)", (long)httpStatus]));
            }
            return;
        }

        NSString *raw = [[NSString alloc] initWithData:validateData encoding:NSUTF8StringEncoding];
        if (raw) {
            NSString *preview = (ALTVerboseLogging || raw.length <= 300) ? raw : [raw substringToIndex:300];
            NSLog(@"[2FA] Validate response: %@", preview);
        }

        NSError *parseError = nil;
        NSDictionary *responseDictionary = PlistDeserialize(validateData, &parseError);
        if (!responseDictionary) {
            completion(NO, parseError ?: SRPError(kAltSignErrorCodeGeneric, @"Invalid 2FA response plist"));
            return;
        }

        // validate endpoint returns flat plist (ec, em, atxid, idmsdata) not nested Response/Status
        NSInteger errorCode = [responseDictionary[@"ec"] integerValue];
        if (errorCode != 0) {
            NSString *errorDescription = responseDictionary[@"em"] ?: @"2FA verification failed";
            NSLog(@"[2FA] Validation failed: ec=%ld, em=%@", (long)errorCode, errorDescription);
            completion(NO, SRPError(errorCode, errorDescription));
            return;
        }

        NSLog(@"[2FA] Validation successful");
        completion(YES, nil);
    }];

    [validateTask resume];
}

+ (int)runNetworkDiagnose {
    NSURL *url = [NSURL URLWithString:kGSAEndpoint];
    NSURLSession *shared = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
    NSOperatingSystemVersion ver = NSProcessInfo.processInfo.operatingSystemVersion;
    NSString *clientInfo = [NSString stringWithFormat:
        @"<Mac> <macOS;%ld.%ld.%ld;unknown>",
        (long)ver.majorVersion, (long)ver.minorVersion, (long)ver.patchVersion];
    NSDictionary *clientHeaders = @{
        @"User-Agent": GSAUserAgent(),
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": kGSAXcodeVersion,
        @"X-MMe-Client-Info": clientInfo,
    };

    void (^emit)(NSString *, NSString *, NSString *, NSInteger, NSString *, long, NSString *, NSString *) =
        ^(NSString *ident, NSString *method, NSString *stage, NSInteger status, NSString *content, long ms, NSString *proxy, NSString *transport) {
            NSMutableString *line = [NSMutableString stringWithFormat:
                @"EVENT:diag id=%@ method=%@ stage=%@ status=%ld content=%@ duration_ms=%ld proxy=%@",
                ident, method, stage, (long)status, content, ms, proxy];
            if (transport.length > 0) {
                [line appendFormat:@" transport=%@", transport];
            }
            fprintf(stdout, "%s\n", line.UTF8String);
            fflush(stdout);
        };

    void (^getOnce)(NSString *, NSString *, NSURLSession *, NSDictionary *, NSString *, void (^)(void)) =
        ^(NSString *ident, NSString *stage, NSURLSession *session, NSDictionary *headers, NSString *proxy, void (^next)(void)) {
            NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
            request.HTTPMethod = @"GET";
            for (NSString *key in headers) {
                [request setValue:headers[key] forHTTPHeaderField:key];
            }
            NSDate *started = [NSDate date];
            NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                NSHTTPURLResponse *http = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
                long ms = (long)([[NSDate date] timeIntervalSinceDate:started] * 1000.0);
                emit(ident, @"GET", stage, http ? http.statusCode : 0,
                     error ? @"transport" : GSAContentKind(data, http),
                     ms, proxy, error ? @"failed" : nil);
                next();
            }];
            [task resume];
        };

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    getOnce(@"A", @"baseline", shared, @{}, @"default", ^{
        getOnce(@"B", @"client-id", shared, clientHeaders, @"default", ^{
            [ALTAnisetteData fetchAnisetteDataWithCompletion:^(ALTAnisetteData *anisette, NSError *anisetteError) {
                void (^runD)(void) = ^{
                    NSDictionary *systemProxy = nil;
                    BOOL pacOnly = NO;
                    CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
                    if (settings) {
                        NSDictionary *dict = CFBridgingRelease(settings);
                        BOOL httpsOn = [dict[(__bridge id)kCFNetworkProxiesHTTPSEnable] boolValue];
                        NSString *host = dict[(__bridge id)kCFNetworkProxiesHTTPSProxy];
                        NSNumber *port = dict[(__bridge id)kCFNetworkProxiesHTTPSPort];
                        BOOL pacOn = [dict[(__bridge id)kCFNetworkProxiesProxyAutoConfigEnable] boolValue];
                        if (httpsOn && [host isKindOfClass:NSString.class] && host.length > 0) {
                            systemProxy = @{
                                (__bridge id)kCFNetworkProxiesHTTPSEnable: @YES,
                                (__bridge id)kCFNetworkProxiesHTTPSProxy: host,
                                (__bridge id)kCFNetworkProxiesHTTPSPort: port ?: @443,
                                (__bridge id)kCFNetworkProxiesHTTPEnable: @NO
                            };
                        } else if (pacOn) {
                            pacOnly = YES;
                        }
                    }
                    if (!systemProxy) {
                        fprintf(stdout, "EVENT:diag id=D method=GET stage=path status=0 content=skipped duration_ms=0 proxy=skipped reason=%s\n",
                                pacOnly ? "pac_only" : "no_system_https_proxy");
                        fflush(stdout);
                        dispatch_semaphore_signal(done);
                        return;
                    }
                    NSURLSessionConfiguration *directConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
                    directConfig.connectionProxyDictionary = @{
                        (__bridge id)kCFNetworkProxiesHTTPEnable: @NO,
                        (__bridge id)kCFNetworkProxiesHTTPSEnable: @NO
                    };
                    NSURLSessionConfiguration *explicitConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
                    explicitConfig.connectionProxyDictionary = systemProxy;
                    NSURLSession *direct = [NSURLSession sessionWithConfiguration:directConfig];
                    NSURLSession *explicitSession = [NSURLSession sessionWithConfiguration:explicitConfig];
                    getOnce(@"D-direct", @"path", direct, @{}, @"direct", ^{
                        getOnce(@"D-explicit", @"path", explicitSession, @{}, @"explicit", ^{
                            dispatch_semaphore_signal(done);
                        });
                    });
                };

                if (!anisette || anisetteError) {
                    emit(@"C", @"GET", @"anisette", 0, @"skipped", 0, @"default", @"anisette_unavailable");
                    runD();
                    return;
                }
                fprintf(stdout, "EVENT:diag id=C-meta method=GET stage=anisette status=0 content=headers duration_ms=0 proxy=default anisette=%s mid=%s otp=%s\n",
                        "present",
                        anisette.machineID.length > 0 ? "set" : "empty",
                        anisette.oneTimePassword.length > 0 ? "set" : "empty");
                fflush(stdout);
                NSDictionary *anisetteHeaders = [anisette httpHeaders];
                NSArray<NSString *> *anisetteKeys = [anisetteHeaders.allKeys sortedArrayUsingSelector:@selector(compare:)];
                __block NSUInteger keyIndex = 0;
                __block void (^nextAnisetteKey)(void) = nil;
                nextAnisetteKey = ^{
                    if (keyIndex >= anisetteKeys.count) {
                        NSMutableDictionary *headers = [clientHeaders mutableCopy];
                        [headers addEntriesFromDictionary:anisetteHeaders];
                        getOnce(@"C", @"anisette", shared, headers, @"default", runD);
                        return;
                    }
                    NSString *key = anisetteKeys[keyIndex++];
                    NSMutableDictionary *one = [clientHeaders mutableCopy];
                    one[key] = anisetteHeaders[key];
                    getOnce([NSString stringWithFormat:@"C-%@", key], @"anisette-one", shared, one, @"default", nextAnisetteKey);
                };
                nextAnisetteKey();
            }];
        });
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    return 0;
}

@end
