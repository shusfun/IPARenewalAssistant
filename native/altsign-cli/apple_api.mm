//
//  apple_api.mm
//  AltSign CLI
//
//  Apple Developer Services API — 参照 AltSign/ALTAppleAPI.m 实现
//  两套协议：
//    Plist API:  baseURL (QH65B2/) + XML plist body + X-Apple-GS-Token 认证
//    Services API: servicesBaseURL (v1/) + JSON body + 同样的认证头
//

#import "apple_api.h"
#import "certificate_request.h"
#import "srp_auth.h"
#import "keychain.h"
#import <Security/Security.h>
#import <Security/SecImportExport.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>

static NSString *HexFromBytes(const unsigned char *bytes, int length)
{
    if (!bytes || length <= 0) return @"";
    NSMutableString *hex = [NSMutableString stringWithCapacity:(NSUInteger)length * 2];
    for (int i = 0; i < length; i++) {
        [hex appendFormat:@"%02X", bytes[i]];
    }
    return hex;
}

NSString *ALTNormalizedCertificateSerial(NSString *value)
{
    if (value.length == 0) return @"";
    NSString *hex = [[[value uppercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                     stringByReplacingOccurrencesOfString:@" " withString:@""];
    hex = [hex stringByReplacingOccurrencesOfString:@":" withString:@""];
    NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"] invertedSet];
    if ([hex rangeOfCharacterFromSet:nonHex].location != NSNotFound) {
        return hex;
    }
    while (hex.length > 1 && [hex hasPrefix:@"0"]) {
        hex = [hex substringFromIndex:1];
    }
    return hex;
}

static NSString *NormalizedCertificateSerial(NSString *value)
{
    return ALTNormalizedCertificateSerial(value);
}

static BOOL CertificateSerialsEqual(NSString *left, NSString *right)
{
    NSString *normalizedLeft = NormalizedCertificateSerial(left);
    NSString *normalizedRight = NormalizedCertificateSerial(right);
    return normalizedLeft.length > 0 && normalizedRight.length > 0 && [normalizedLeft isEqualToString:normalizedRight];
}

static NSString *SerialFromCertificateData(NSData *data)
{
    if (data.length == 0) return nil;
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    X509 *cert = d2i_X509(NULL, &bytes, (long)data.length);
    if (!cert) {
        BIO *bio = BIO_new_mem_buf(data.bytes, (int)data.length);
        PEM_read_bio_X509(bio, &cert, 0, 0);
        BIO_free(bio);
    }
    if (!cert) return nil;
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    NSString *hex = nil;
    if (serial && serial->data && serial->length > 0) {
        hex = HexFromBytes(serial->data, serial->length);
    }
    X509_free(cert);
    return hex;
}

static BOOL CertificateMatchesSerial(ALTCertificate *certificate, NSString *serialNum)
{
    if (serialNum.length == 0 || !certificate) return NO;
    if (CertificateSerialsEqual(serialNum, certificate.serialNumber) || CertificateSerialsEqual(serialNum, certificate.identifier)) {
        return YES;
    }
    return CertificateSerialsEqual(serialNum, SerialFromCertificateData(certificate.data));
}

static NSData *PEMFromSecKey(SecKeyRef key)
{
    if (!key) return nil;
    if (ALTKeychainAccessWasDenied()) return nil;
    CFDataRef exported = NULL;
    OSStatus status = SecItemExport(key, kSecFormatOpenSSL, kSecItemPemArmour, NULL, &exported);
    if (status == errSecSuccess && exported) {
        return CFBridgingRelease(exported);
    }
    if (exported) {
        CFRelease(exported);
        exported = NULL;
    }
    if (ALTKeychainOSStatusIsDenied(status)) {
        ALTKeychainMarkAccessDenied();
        return nil;
    }
    CFErrorRef error = NULL;
    CFDataRef raw = SecKeyCopyExternalRepresentation(key, &error);
    if (error) CFRelease(error);
    if (!raw) return nil;
    NSData *bytes = CFBridgingRelease(raw);
    NSString *b64 = [bytes base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithLineFeed];
    NSString *pem = [NSString stringWithFormat:@"-----BEGIN RSA PRIVATE KEY-----\n%@\n-----END RSA PRIVATE KEY-----\n", b64];
    return [pem dataUsingEncoding:NSUTF8StringEncoding];
}

NSData *ALTCopyPrivateKeyFromSystemKeychain(ALTCertificate *certificate)
{
    if (!certificate) return nil;
    if (ALTKeychainAccessWasDenied()) return nil;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassIdentity,
        (__bridge id)kSecReturnRef: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) {
        if (result) CFRelease(result);
        (void)ALTKeychainStatusFromOSStatus(status == errSecSuccess ? errSecItemNotFound : status);
        return nil;
    }
    NSArray *identities = CFBridgingRelease(result);
    NSString *portalDERSerial = SerialFromCertificateData(certificate.data);
    SecCertificateRef portalCert = certificate.data.length > 0
        ? SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate.data)
        : NULL;
    CFDataRef portalDER = portalCert ? SecCertificateCopyData(portalCert) : NULL;

    NSData *found = nil;
    for (id identityObj in identities) {
        SecIdentityRef identity = (__bridge SecIdentityRef)identityObj;
        SecCertificateRef localCert = NULL;
        if (SecIdentityCopyCertificate(identity, &localCert) != errSecSuccess || !localCert) continue;
        BOOL match = NO;
        CFErrorRef serialError = NULL;
        CFDataRef serialData = SecCertificateCopySerialNumberData(localCert, &serialError);
        if (serialError) CFRelease(serialError);
        if (serialData) {
            NSString *hex = HexFromBytes(CFDataGetBytePtr(serialData), (int)CFDataGetLength(serialData));
            CFRelease(serialData);
            if (CertificateMatchesSerial(certificate, hex) || CertificateSerialsEqual(hex, portalDERSerial)) {
                match = YES;
            }
        }
        if (!match && portalDER) {
            CFDataRef localDER = SecCertificateCopyData(localCert);
            if (localDER) {
                match = CFEqual(localDER, portalDER);
                CFRelease(localDER);
            }
        }
        CFRelease(localCert);
        if (!match) continue;
        SecKeyRef privateKey = NULL;
        OSStatus keyStatus = SecIdentityCopyPrivateKey(identity, &privateKey);
        if (keyStatus != errSecSuccess || !privateKey) {
            if (privateKey) CFRelease(privateKey);
            if (ALTKeychainOSStatusIsDenied(keyStatus)) {
                ALTKeychainMarkAccessDenied();
                found = nil;
                break;
            }
            continue;
        }
        found = PEMFromSecKey(privateKey);
        CFRelease(privateKey);
        if (ALTKeychainAccessWasDenied()) {
            found = nil;
            break;
        }
        if (found) break;
    }

    if (portalDER) CFRelease(portalDER);
    if (portalCert) CFRelease(portalCert);
    return found;
}

static NSString *X509NameValue(X509 *cert, int nid)
{
    if (!cert) return nil;
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject) return nil;
    int count = X509_NAME_entry_count(subject);
    for (int i = 0; i < count; i++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
        if (!entry) continue;
        if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry)) != nid) continue;
        ASN1_STRING *value = X509_NAME_ENTRY_get_data(entry);
        if (!value) continue;
        const unsigned char *bytes = ASN1_STRING_get0_data(value);
        int length = ASN1_STRING_length(value);
        if (!bytes || length <= 0) continue;
        return [[NSString alloc] initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static BOOL CertificateDataBelongsToTeam(NSData *data, NSString *teamID)
{
    if (data.length == 0 || teamID.length == 0) return NO;
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    X509 *cert = d2i_X509(NULL, &bytes, (long)data.length);
    if (!cert) return NO;
    NSString *ou = X509NameValue(cert, NID_organizationalUnitName);
    NSString *cn = X509NameValue(cert, NID_commonName) ?: @"";
    X509_free(cert);
    BOOL teamOK = [ou isEqualToString:teamID];
    BOOL development = [cn containsString:@"Apple Development"] ||
                       [cn containsString:@"iPhone Developer"] ||
                       [cn containsString:@"iOS Development"];
    return teamOK && development;
}

NSData *ALTCopyTeamIdentityFromSystemKeychain(NSString *teamID, ALTCertificate * _Nullable * _Nullable outCertificate)
{
    if (outCertificate) *outCertificate = nil;
    if (teamID.length == 0) return nil;
    if (ALTKeychainAccessWasDenied()) return nil;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassIdentity,
        (__bridge id)kSecReturnRef: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) {
        if (result) CFRelease(result);
        (void)ALTKeychainStatusFromOSStatus(status == errSecSuccess ? errSecItemNotFound : status);
        return nil;
    }
    NSArray *identities = CFBridgingRelease(result);
    for (id identityObj in identities) {
        SecIdentityRef identity = (__bridge SecIdentityRef)identityObj;
        SecCertificateRef localCert = NULL;
        if (SecIdentityCopyCertificate(identity, &localCert) != errSecSuccess || !localCert) continue;
        CFDataRef derRef = SecCertificateCopyData(localCert);
        CFRelease(localCert);
        if (!derRef) continue;
        NSData *der = CFBridgingRelease(derRef);
        if (!CertificateDataBelongsToTeam(der, teamID)) continue;
        SecKeyRef privateKey = NULL;
        OSStatus keyStatus = SecIdentityCopyPrivateKey(identity, &privateKey);
        if (keyStatus != errSecSuccess || !privateKey) {
            if (privateKey) CFRelease(privateKey);
            if (ALTKeychainOSStatusIsDenied(keyStatus)) {
                ALTKeychainMarkAccessDenied();
                return nil;
            }
            continue;
        }
        NSData *pem = PEMFromSecKey(privateKey);
        CFRelease(privateKey);
        if (ALTKeychainAccessWasDenied()) return nil;
        if (!pem) continue;
        ALTCertificate *certificate = [[ALTCertificate alloc] init];
        certificate.data = der;
        certificate.serialNumber = SerialFromCertificateData(der);
        certificate.identifier = certificate.serialNumber ?: teamID;
        if (outCertificate) *outCertificate = certificate;
        NSLog(@"[API] Reusing Apple Development identity for team %@", teamID);
        return pem;
    }
    return nil;
}

static NSString *const kProtocolVersion = @"QH65B2";
static NSString *const kClientID = @"XABBG36SBA";
static NSString *const kBaseURL = @"https://developerservices2.apple.com/services/QH65B2/";
static NSString *const kServicesBaseURL = @"https://developerservices2.apple.com/services/v1/";

// ============================================================
// 数据模型
// ============================================================

@implementation ALTTeam
@end

@implementation ALTCertificate

- (nullable NSData *)p12Data
{
    if (!self.data || !self.privateKey) return nil;

    // 同时尝试 DER 和 PEM 格式读取证书
    X509 *cert = NULL;
    const unsigned char *certBytes = (const unsigned char *)self.data.bytes;

    // 先尝试 DER 格式
    cert = d2i_X509(NULL, &certBytes, self.data.length);

    // DER 失败则尝试 PEM 格式
    if (!cert) {
        BIO *certBIO = BIO_new_mem_buf(self.data.bytes, (int)self.data.length);
        PEM_read_bio_X509(certBIO, &cert, 0, 0);
        BIO_free(certBIO);
    }

    if (!cert) {
        NSLog(@"[P12] Failed to parse certificate (tried DER and PEM)");
        return nil;
    }

    BIO *keyBIO = BIO_new_mem_buf(self.privateKey.bytes, (int)self.privateKey.length);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keyBIO, NULL, NULL, NULL);
    BIO_free(keyBIO);
    if (!pkey) {
        NSLog(@"[P12] Failed to parse private key");
        X509_free(cert);
        return nil;
    }
    if (X509_check_private_key(cert, pkey) != 1) {
        NSLog(@"[P12] Private key does not match certificate");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return nil;
    }

    char pass[] = "altsign";
    PKCS12 *p12 = PKCS12_create(pass, "IPARenewalAssistant", pkey, cert, NULL,
                                 NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                 NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                 2048, 1, 0);
    // macOS security import 不支持 SHA-256 MAC，强制使用 SHA-1
    if (p12) {
        PKCS12_set_mac(p12, pass, -1, NULL, 0, 1, EVP_sha1());
    }
    if (!p12) {
        NSLog(@"[P12] PKCS12_create failed");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return nil;
    }

    BIO *outputBIO = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(outputBIO, p12);

    char *outputData = NULL;
    long outputLength = BIO_get_mem_data(outputBIO, &outputData);
    NSData *result = [NSData dataWithBytes:outputData length:outputLength];

    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free_all(outputBIO);

    NSLog(@"[P12] Generated %ld bytes", outputLength);
    return result;
}

@end

@implementation ALTDevice
@end

@implementation ALTAppID
@end

@implementation ALTProvisioningProfile
@end

// ============================================================
// ALTAppleAPI
// ============================================================

@interface ALTAppleAPI ()
@property (nonatomic, strong) NSURLSession *urlSession;
@property (nonatomic, strong) NSDateFormatter *dateFormatter;
@end

@implementation ALTAppleAPI

+ (instancetype)sharedAPI {
    static ALTAppleAPI *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[ALTAppleAPI alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _urlSession = [NSURLSession sessionWithConfiguration:
            [NSURLSessionConfiguration ephemeralSessionConfiguration]];
        _dateFormatter = [[NSDateFormatter alloc] init];
        _dateFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
        _dateFormatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
    }
    return self;
}

// ============================================================
// Plist API — 通用请求发送器
// ============================================================

- (void)sendRequestWithURL:(NSURL *)requestURL
        additionalParameters:(NSDictionary<NSString *, NSString *> * _Nullable)additionalParameters
                     session:(ALTAppleAPISession *)session
                        team:(ALTTeam * _Nullable)team
           completionHandler:(void (^)(NSDictionary * _Nullable, NSError * _Nullable))completionHandler
{
    NSMutableDictionary<NSString *, NSString *> *parameters = [@{
        @"clientId": kClientID,
        @"protocolVersion": kProtocolVersion,
        @"requestId": [[[NSUUID UUID] UUIDString] uppercaseString],
    } mutableCopy];

    if (team) {
        parameters[@"teamId"] = team.identifier;
    }

    [additionalParameters enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        parameters[key] = value;
    }];

    NSData *bodyData = [NSPropertyListSerialization dataWithPropertyList:parameters
                                                                  format:NSPropertyListXMLFormat_v1_0
                                                                 options:0
                                                                   error:nil];
    if (!bodyData) {
        completionHandler(nil, [NSError errorWithDomain:@"com.altsign.api" code:-1
                                               userInfo:@{NSLocalizedDescriptionKey: @"Failed to serialize plist"}]);
        return;
    }

    NSURL *URL = [NSURL URLWithString:[NSString stringWithFormat:@"%@?clientId=%@",
                                       requestURL.absoluteString, kClientID]];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;

    NSDictionary<NSString *, NSString *> *httpHeaders = @{
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": @"Xcode",
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": @"26.0 (17A324)",
        @"X-Apple-I-Identity-Id": session.dsid,
        @"X-Apple-GS-Token": session.authToken,
        @"X-Apple-I-MD-M": session.anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": session.anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": session.anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(session.anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": session.anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": session.anisetteData.deviceDescription ?: @"",
        @"X-Apple-I-Client-Time": [self.dateFormatter stringFromDate:session.anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": session.anisetteData.locale ?: @"en_US",
        @"X-Apple-I-Locale": session.anisetteData.locale ?: @"en_US",
        @"X-Apple-I-TimeZone": session.anisetteData.timeZone ?: @"UTC",
    };

    for (NSString *key in httpHeaders) {
        [request setValue:httpHeaders[key] forHTTPHeaderField:key];
    }

    NSURLSessionDataTask *task = [self.urlSession dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                completionHandler(nil, error);
                return;
            }

            NSInteger httpStatus = [(NSHTTPURLResponse *)response statusCode];
            NSDictionary *responseDict = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

            if (!responseDict) {
                NSString *raw = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"(empty)";
                NSLog(@"[API] %@ HTTP %ld (not plist): %@", requestURL.lastPathComponent, (long)httpStatus, raw);
                completionHandler(nil, [NSError errorWithDomain:@"com.altsign.api" code:httpStatus
                                                       userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld from %@", (long)httpStatus, requestURL.lastPathComponent]}]);
                return;
            }

            if (ALTVerboseLogging) {
                NSLog(@"[API] %@ → %@", requestURL.lastPathComponent, responseDict);
            }

            // 检查 resultCode
            NSInteger resultCode = [responseDict[@"resultCode"] integerValue];
            if (resultCode != 0) {
                NSString *msg = responseDict[@"userString"] ?: responseDict[@"resultString"] ?: @"Unknown error";
                NSString *desc = [NSString stringWithFormat:@"%@ (resultCode=%ld)", msg, (long)resultCode];
                completionHandler(nil, [NSError errorWithDomain:@"com.altsign.api" code:resultCode
                                                       userInfo:@{NSLocalizedDescriptionKey: desc}]);
                return;
            }

            completionHandler(responseDict, nil);
        }];
    [task resume];
}

// ============================================================
// Services API — JSON 格式（用于 certificates）
// ============================================================

- (void)sendServicesRequest:(NSURLRequest *)originalRequest
         additionalParameters:(NSDictionary<NSString *, NSString *> * _Nullable)additionalParameters
                     session:(ALTAppleAPISession *)session
                        team:(ALTTeam * _Nullable)team
           completionHandler:(void (^)(NSDictionary * _Nullable, NSError * _Nullable))completionHandler
{
    NSMutableURLRequest *request = [originalRequest mutableCopy];

    NSMutableArray<NSURLQueryItem *> *queryItems = [NSMutableArray array];
    if (team) {
        [queryItems addObject:[NSURLQueryItem queryItemWithName:@"teamId" value:team.identifier]];
    }
    [additionalParameters enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [queryItems addObject:[NSURLQueryItem queryItemWithName:key value:value]];
    }];

    NSURLComponents *components = [[NSURLComponents alloc] init];
    components.queryItems = queryItems;
    NSString *queryString = components.query ?: @"";

    NSData *bodyData = [NSJSONSerialization dataWithJSONObject:@{@"urlEncodedQueryParams": queryString} options:0 error:nil];
    request.HTTPBody = bodyData;

    NSString *HTTPMethodOverride = request.HTTPMethod ?: @"GET";
    request.HTTPMethod = @"POST";

    NSDictionary<NSString *, NSString *> *httpHeaders = @{
        @"Content-Type": @"application/vnd.api+json",
        @"User-Agent": @"Xcode",
        @"Accept": @"application/vnd.api+json",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": @"26.0 (17A324)",
        @"X-HTTP-Method-Override": HTTPMethodOverride,
        @"X-Apple-I-Identity-Id": session.dsid,
        @"X-Apple-GS-Token": session.authToken,
        @"X-Apple-I-MD-M": session.anisetteData.machineID ?: @"",
        @"X-Apple-I-MD": session.anisetteData.oneTimePassword ?: @"",
        @"X-Apple-I-MD-LU": session.anisetteData.localUserID ?: @"",
        @"X-Apple-I-MD-RINFO": [@(session.anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": session.anisetteData.deviceUniqueIdentifier ?: @"",
        @"X-MMe-Client-Info": session.anisetteData.deviceDescription ?: @"",
        @"X-Apple-I-Client-Time": [self.dateFormatter stringFromDate:session.anisetteData.date ?: [NSDate date]],
        @"X-Apple-Locale": session.anisetteData.locale ?: @"en_US",
        @"X-Apple-I-Locale": session.anisetteData.locale ?: @"en_US",
        @"X-Apple-I-TimeZone": session.anisetteData.timeZone ?: @"UTC",
    };

    for (NSString *key in httpHeaders) {
        [request setValue:httpHeaders[key] forHTTPHeaderField:key];
    }

    NSURLSessionDataTask *task = [self.urlSession dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                completionHandler(nil, error);
                return;
            }

            NSInteger httpStatus = [(NSHTTPURLResponse *)response statusCode];

            // HTTP 204 = 成功（无内容），用于 DELETE 等操作
            if (httpStatus == 204) {
                completionHandler(@{}, nil);
                return;
            }

            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

            if (!json || httpStatus >= 400) {
                NSString *raw = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"(empty)";
                NSLog(@"[API] %@ HTTP %ld: %@", request.URL.lastPathComponent, (long)httpStatus, raw);
            } else if (ALTVerboseLogging) {
                NSLog(@"[API] %@ HTTP %ld: %@", request.URL.lastPathComponent, (long)httpStatus, json);
            }

            if (!json) {
                completionHandler(nil, [NSError errorWithDomain:@"com.altsign.api" code:httpStatus
                                                       userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"HTTP %ld", (long)httpStatus]}]);
                return;
            }

            // Check for errors in JSON response
            NSArray *errors = json[@"errors"];
            if (errors.count > 0) {
                NSDictionary *err = errors.firstObject;
                NSString *desc = err[@"detail"] ?: err[@"title"] ?: @"Unknown services error";
                NSLog(@"[API] Services error: %@", desc);
                completionHandler(nil, [NSError errorWithDomain:@"com.altsign.api" code:httpStatus
                                                       userInfo:@{NSLocalizedDescriptionKey: desc}]);
                return;
            }

            completionHandler(json, nil);
        }];
    [task resume];
}

// ============================================================
// API 方法
// ============================================================

#pragma mark - Teams

- (void)fetchTeamsForAccount:(ALTAccount *)account
                     session:(ALTAppleAPISession *)session
           completionHandler:(void (^)(NSArray<ALTTeam *> *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"listTeams.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    [self sendRequestWithURL:URL additionalParameters:nil session:session team:nil
        completionHandler:^(NSDictionary *response, NSError *error) {
            if (error) { completion(nil, error); return; }

            NSArray *teamArray = response[@"teams"];
            NSMutableArray<ALTTeam *> *teams = [NSMutableArray array];

            for (NSDictionary *dict in teamArray) {
                ALTTeam *team = [[ALTTeam alloc] init];
                team.identifier = dict[@"teamId"] ?: @"";
                team.name = dict[@"name"] ?: @"";
                team.type = dict[@"type"] ?: @"Individual";
                [teams addObject:team];
            }

            NSLog(@"[API] Found %lu teams", (unsigned long)teams.count);
            completion(teams, nil);
        }];
}

#pragma mark - Certificates

static NSArray<ALTCertificate *> *CertificatesFromServicesResponse(NSDictionary *response)
{
    NSArray *dataArray = response[@"data"];
    NSMutableArray<ALTCertificate *> *certs = [NSMutableArray array];
    for (NSDictionary *dict in dataArray) {
        if (![dict isKindOfClass:[NSDictionary class]]) continue;
        ALTCertificate *cert = [[ALTCertificate alloc] init];
        NSDictionary *attrs = dict[@"attributes"] ?: dict;
        NSString *resourceID = dict[@"id"] ?: @"";
        NSString *serial = attrs[@"serialNumber"] ?: @"";
        cert.name = attrs[@"name"];
        NSString *certContent = attrs[@"certificateContent"] ?: attrs[@"certContent"];
        if (certContent) {
            cert.data = [[NSData alloc] initWithBase64EncodedString:certContent options:0];
        }
        if (serial.length == 0) {
            serial = SerialFromCertificateData(cert.data) ?: @"";
        }
        cert.serialNumber = serial;
        cert.identifier = resourceID.length > 0 ? resourceID : serial;
        [certs addObject:cert];
    }
    return certs;
}

- (void)fetchCertificatesOfType:(NSString *)certificateType
                           team:(ALTTeam *)team
                        session:(ALTAppleAPISession *)session
              completionHandler:(void (^)(NSArray<ALTCertificate *> *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"certificates" relativeToURL:
                  [NSURL URLWithString:kServicesBaseURL]];
    NSURLRequest *req = [NSURLRequest requestWithURL:URL];
    [self sendServicesRequest:req
         additionalParameters:@{@"filter[certificateType]": certificateType}
                      session:session team:team
            completionHandler:^(NSDictionary *response, NSError *error) {
                if (error) {
                    completion(@[], error);
                    return;
                }
                completion(CertificatesFromServicesResponse(response), nil);
            }];
}

- (void)fetchCertificatesForTeam:(ALTTeam *)team
                         session:(ALTAppleAPISession *)session
               completionHandler:(void (^)(NSArray<ALTCertificate *> *, NSError *))completion
{
    [self fetchCertificatesOfType:@"IOS_DEVELOPMENT" team:team session:session completionHandler:^(NSArray<ALTCertificate *> *iosCerts, NSError *iosError) {
        [self fetchCertificatesOfType:@"DEVELOPMENT" team:team session:session completionHandler:^(NSArray<ALTCertificate *> *devCerts, NSError *devError) {
            if ((iosError && devError) && iosCerts.count == 0 && devCerts.count == 0) {
                completion(nil, iosError ?: devError);
                return;
            }
            NSMutableArray<ALTCertificate *> *certs = [NSMutableArray array];
            NSMutableSet<NSString *> *seen = [NSMutableSet set];
            for (ALTCertificate *cert in [(iosCerts ?: @[]) arrayByAddingObjectsFromArray:(devCerts ?: @[])]) {
                NSString *key = cert.identifier.length ? cert.identifier : (cert.serialNumber ?: @"");
                if (key.length == 0 || [seen containsObject:key]) continue;
                [seen addObject:key];
                [certs addObject:cert];
            }
            NSLog(@"[API] Found %lu certificates (ios=%lu development=%lu)", (unsigned long)certs.count, (unsigned long)iosCerts.count, (unsigned long)devCerts.count);
            completion(certs, nil);
        }];
    }];
}

- (void)submitCertificateRequest:(NSData *)csrData
                            team:(ALTTeam *)team
                         session:(ALTAppleAPISession *)session
               completionHandler:(void (^)(ALTCertificate *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/submitDevelopmentCSR.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    NSString *csrContent = [[NSString alloc] initWithData:csrData encoding:NSUTF8StringEncoding];

    [self sendRequestWithURL:URL
         additionalParameters:@{
             @"csrContent": csrContent ?: @"",
             @"machineId": [[NSUUID UUID] UUIDString],
             @"machineName": @"AltSign Device"
         }
                      session:session team:team
            completionHandler:^(NSDictionary *response, NSError *error) {
                if (error) { completion(nil, error); return; }

                NSDictionary *certDict = response[@"certRequest"];
                NSString *serialNum = certDict[@"serialNum"];
                NSLog(@"[API] CSR submitted: serialNum=%@ status=%@", serialNum, certDict[@"statusString"]);

                // CSR 响应不含证书 DER 数据，需要重新拉取证书列表并按序列号匹配。
                [self fetchCertificatesForTeam:team session:session completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *fetchError) {
                    if (fetchError || certs.count == 0) {
                        completion(nil, fetchError ?: [NSError errorWithDomain:@"com.altsign" code:-1
                            userInfo:@{NSLocalizedDescriptionKey: @"Certificate created but not found in list"}]);
                        return;
                    }
                    ALTCertificate *cert = nil;
                    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
                    for (ALTCertificate *candidate in certs) {
                        NSString *derSerial = SerialFromCertificateData(candidate.data) ?: @"";
                        [candidates addObject:[NSString stringWithFormat:@"id=%@ serial=%@ der=%@", candidate.identifier ?: @"", candidate.serialNumber ?: @"", derSerial]];
                        if (CertificateMatchesSerial(candidate, serialNum)) {
                            cert = candidate;
                            break;
                        }
                    }
                    if (!cert && certs.count == 1 && serialNum.length > 0) {
                        NSLog(@"[API] CSR serial form differed; using the only team certificate after approval");
                        cert = certs.firstObject;
                    }
                    if (!cert) {
                        NSLog(@"[API] Certificate serial mismatch: csr=%@ candidates=%@", serialNum, [candidates componentsJoinedByString:@"; "]);
                        NSMutableDictionary *info = [@{NSLocalizedDescriptionKey: @"Certificate created but serial number did not match any team certificate"} mutableCopy];
                        if (serialNum.length > 0) info[@"serialNum"] = serialNum;
                        completion(nil, [NSError errorWithDomain:@"com.altsign" code:-1 userInfo:info]);
                        return;
                    }
                    NSLog(@"[API] Certificate fetched after CSR: %@ (hasData=%d)", cert.identifier, (cert.data != nil));
                    completion(cert, nil);
                }];
            }];
}

- (void)revokeCertificate:(ALTCertificate *)certificate
                      team:(ALTTeam *)team
                   session:(ALTAppleAPISession *)session
         completionHandler:(void (^)(BOOL, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:[NSString stringWithFormat:@"certificates/%@", certificate.identifier]
                      relativeToURL:[NSURL URLWithString:kServicesBaseURL]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:URL];
    req.HTTPMethod = @"DELETE";

    [self sendServicesRequest:req additionalParameters:nil session:session team:team
        completionHandler:^(NSDictionary *response, NSError *error) {
            if (error) { completion(NO, error); return; }
            NSLog(@"[API] Certificate revoked: %@", certificate.identifier);
            completion(YES, nil);
        }];
}

#pragma mark - Devices

- (void)registerDeviceWithName:(NSString *)name
                    identifier:(NSString *)udid
                          team:(ALTTeam *)team
                       session:(ALTAppleAPISession *)session
             completionHandler:(void (^)(ALTDevice *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/addDevice.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    [self sendRequestWithURL:URL
         additionalParameters:@{@"deviceNumber": udid, @"name": name}
                      session:session team:team
            completionHandler:^(NSDictionary *response, NSError *error) {
                if (error) {
                    // resultCode 35 + "already exists" → 设备已注册，不算错误
                    NSString *desc = error.localizedDescription;
                    if ([desc containsString:@"already exists"]) {
                        NSLog(@"[API] Device already registered, continuing...");
                        ALTDevice *device = [[ALTDevice alloc] init];
                        device.identifier = udid;
                        device.name = name;
                        completion(device, nil);
                        return;
                    }
                    completion(nil, error);
                    return;
                }

                NSDictionary *deviceDict = response[@"device"];
                ALTDevice *device = [[ALTDevice alloc] init];
                device.identifier = deviceDict[@"deviceNumber"] ?: udid;
                device.name = deviceDict[@"name"] ?: name;

                NSLog(@"[API] Device registered: %@ (%@)", device.name, device.identifier);
                completion(device, nil);
            }];
}

#pragma mark - App IDs

- (void)fetchAppIDsForTeam:(ALTTeam *)team
                   session:(ALTAppleAPISession *)session
         completionHandler:(void (^)(NSArray<ALTAppID *> * _Nullable, NSError * _Nullable))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/listAppIds.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    [self sendRequestWithURL:URL additionalParameters:nil session:session team:team
        completionHandler:^(NSDictionary *response, NSError *error) {
            if (error) { completion(nil, error); return; }

            NSArray *array = response[@"appIds"] ?: @[];
            NSMutableArray<ALTAppID *> *appIDs = [NSMutableArray array];
            for (NSDictionary *dict in array) {
                ALTAppID *appID = [[ALTAppID alloc] init];
                appID.identifier = dict[@"appIdId"] ?: @"";
                appID.bundleIdentifier = dict[@"identifier"] ?: @"";
                appID.name = dict[@"name"] ?: @"";
                [appIDs addObject:appID];
            }
            NSLog(@"[API] Found %lu App IDs", (unsigned long)appIDs.count);
            completion(appIDs, nil);
        }];
}

- (void)addAppIDWithName:(NSString *)name
        bundleIdentifier:(NSString *)bundleIdentifier
                    team:(ALTTeam *)team
                 session:(ALTAppleAPISession *)session
       completionHandler:(void (^)(ALTAppID *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/addAppId.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    NSMutableCharacterSet *allowed = [NSMutableCharacterSet alphanumericCharacterSet];
    [allowed addCharactersInString:@".-"];
    NSString *sanitized = [[name componentsSeparatedByCharactersInSet:
        [allowed invertedSet]] componentsJoinedByString:@""];

    [self sendRequestWithURL:URL
         additionalParameters:@{@"identifier": bundleIdentifier, @"name": sanitized}
                      session:session team:team
            completionHandler:^(NSDictionary *response, NSError *error) {
                if (error) { completion(nil, error); return; }

                NSDictionary *appDict = response[@"appId"];
                ALTAppID *appID = [[ALTAppID alloc] init];
                appID.identifier = appDict[@"appIdId"] ?: @"";
                appID.bundleIdentifier = appDict[@"identifier"] ?: bundleIdentifier;
                appID.name = appDict[@"name"] ?: name;

                NSLog(@"[API] App ID created: %@", appID.bundleIdentifier);
                completion(appID, nil);
            }];
}

- (void)updateAppID:(ALTAppID *)appID
            features:(NSDictionary<NSString *, id> *)features
                team:(ALTTeam *)team
             session:(ALTAppleAPISession *)session
   completionHandler:(void (^)(ALTAppID *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/updateAppId.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    NSMutableDictionary *params = [@{@"appIdId": appID.identifier} mutableCopy];
    [features enumerateKeysAndObjectsUsingBlock:^(NSString *key, id value, BOOL *stop) {
        params[key] = value;
    }];

    [self sendRequestWithURL:URL additionalParameters:params session:session team:team
        completionHandler:^(NSDictionary *response, NSError *error) {
            if (error) { completion(nil, error); return; }

            NSDictionary *appDict = response[@"appId"];
            ALTAppID *updated = [[ALTAppID alloc] init];
            updated.identifier = appDict[@"appIdId"] ?: appID.identifier;
            updated.bundleIdentifier = appDict[@"identifier"] ?: appID.bundleIdentifier;
            updated.name = appDict[@"name"] ?: appID.name;

            NSArray *enabled = appDict[@"enabledFeatures"];
            NSLog(@"[API] App ID updated: %@, enabledFeatures: %@", updated.bundleIdentifier, enabled);
            completion(updated, nil);
        }];
}

#pragma mark - Provisioning Profiles

- (void)fetchProvisioningProfileForAppID:(ALTAppID *)appID
                                    team:(ALTTeam *)team
                                 session:(ALTAppleAPISession *)session
                       completionHandler:(void (^)(ALTProvisioningProfile *, NSError *))completion
{
    NSURL *URL = [NSURL URLWithString:@"ios/downloadTeamProvisioningProfile.action" relativeToURL:
                  [NSURL URLWithString:kBaseURL]];

    [self sendRequestWithURL:URL
         additionalParameters:@{@"appIdId": appID.identifier}
                      session:session team:team
            completionHandler:^(NSDictionary *response, NSError *error) {
                if (error) { completion(nil, error); return; }

                NSDictionary *profileDict = response[@"provisioningProfile"];
                ALTProvisioningProfile *profile = [[ALTProvisioningProfile alloc] init];
                profile.identifier = profileDict[@"UUID"] ?: @"";
                profile.bundleIdentifier = appID.bundleIdentifier;

                // encodedProfile 可能已经是 NSData（plist 自动解码）或 NSString（需手动 base64 解码）
                id encodedProfile = profileDict[@"encodedProfile"] ?: profileDict[@"profileContent"];
                if ([encodedProfile isKindOfClass:[NSData class]]) {
                    profile.data = encodedProfile;
                } else if ([encodedProfile isKindOfClass:[NSString class]]) {
                    profile.data = [[NSData alloc] initWithBase64EncodedString:encodedProfile options:0];
                }
                NSLog(@"[API] Profile data: %lu bytes", (unsigned long)profile.data.length);

                // 解析 mobileprovision 中的 entitlements
                if (profile.data) {
                    NSString *profileStr = [[NSString alloc] initWithData:profile.data
                        encoding:NSASCIIStringEncoding];
                    NSRange plistStart = [profileStr rangeOfString:@"<?xml"];
                    NSRange plistEnd = [profileStr rangeOfString:@"</plist>"];

                    if (plistStart.location != NSNotFound && plistEnd.location != NSNotFound) {
                        NSRange plistRange = NSMakeRange(plistStart.location,
                            plistEnd.location + plistEnd.length - plistStart.location);
                        NSString *plistStr = [profileStr substringWithRange:plistRange];
                        NSData *plistData = [plistStr dataUsingEncoding:NSUTF8StringEncoding];
                        NSDictionary *plist = [NSPropertyListSerialization
                            propertyListWithData:plistData options:0 format:nil error:nil];

                        profile.entitlements = plist[@"Entitlements"];
                        profile.expirationDate = plist[@"ExpirationDate"];
                    }
                }

                NSLog(@"[API] Profile fetched: %@ (expires: %@)",
                      profile.identifier, profile.expirationDate);
                completion(profile, nil);
            }];
}

@end
