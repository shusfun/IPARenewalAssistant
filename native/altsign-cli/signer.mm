//
//  signer.mm
//  AltSign CLI
//
//  IPA re-signing via codesign (targeted signing, preserves Apple frameworks)
//

#import "signer.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <stdio.h>
#include <stdlib.h>

static void emitSignEvent(NSString *step, NSString *status, NSString *reason) {
    fprintf(stderr, "EVENT:sign step=%s status=%s reason=%s\n",
            (step.length > 0 ? step.UTF8String : "unknown"),
            (status.length > 0 ? status.UTF8String : "unknown"),
            (reason.length > 0 ? reason.UTF8String : "unknown"));
    fflush(stderr);
}

static NSURL *altsignMakeWorkDirectory(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    const char *env = getenv("IPARENEWAL_WORK_DIR");
    NSURL *base = (env && env[0] != '\0')
        ? [NSURL fileURLWithPath:@(env) isDirectory:YES]
        : fm.temporaryDirectory;
    NSURL *dir = [base URLByAppendingPathComponent:[[NSUUID UUID] UUIDString] isDirectory:YES];
    [fm createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:nil];
    return dir;
}

static NSString *LoginKeychainPath(void) {
    NSString *db = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Keychains/login.keychain-db"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:db]) return db;
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Keychains/login.keychain"];
}

static NSString *SHA1HexFromData(NSData *data) {
    if (data.length == 0) return nil;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02X", digest[i]];
    }
    return hex;
}

static NSString *CodesignFailureReason(NSString *output) {
    NSString *lower = output.lowercaseString ?: @"";
    if ([lower containsString:@"errsecinternalcomponent"] || [lower containsString:@"cssmerr"]) return @"keychain";
    if ([lower containsString:@"no identity"] || [lower containsString:@"could not find identity"] || [lower containsString:@"identity not found"]) return @"no-identity";
    if ([lower containsString:@"entitlement"]) return @"entitlements";
    if ([lower containsString:@"busy"] || [lower containsString:@"in use"] || [lower containsString:@"resource busy"]) return @"busy";
    return @"unknown";
}

static NSString *FingerprintFromIdentityOutput(NSString *output) {
    if (output.length == 0) return nil;
    NSRegularExpression *regex = [NSRegularExpression
        regularExpressionWithPattern:@"\\b([0-9A-Fa-f]{40})\\b"
                             options:NSRegularExpressionCaseInsensitive
                               error:nil];
    NSTextCheckingResult *match = [regex firstMatchInString:output options:0
        range:NSMakeRange(0, output.length)];
    return match ? [output substringWithRange:[match rangeAtIndex:1]] : nil;
}

@interface ALTSigner ()
@property (nonatomic, strong) ALTCertificate *certificate;
- (void)signPayloadInTemporaryDirectory:(NSURL *)tempDir
                                 appURL:(NSURL *)appURL
                   provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
                              outputURL:(NSURL *)outputURL
                      completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion;
- (int)runTask:(NSString *)launchPath args:(NSArray *)args output:(NSString *_Nullable *_Nullable)outOutput;
- (int)codesignPath:(NSString *)path identity:(NSString *)identity entitlements:(NSString *)entitlements output:(NSString **)outOutput;
- (void)ensureWWDRCertificatesInKeychain:(NSString *)loginPath;
@end

@implementation ALTSigner

- (instancetype)initWithCertificate:(ALTCertificate *)certificate {
    self = [super init];
    if (self) {
        _certificate = certificate;
    }
    return self;
}

#pragma mark - Main Signing Flow

- (void)signIPAAtURL:(NSURL *)ipaURL
provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
           outputURL:(NSURL *)outputURL
   completionHandler:(void (^)(BOOL, NSError *))completion
{
    NSFileManager *fm = [NSFileManager defaultManager];
    // Step 1: 解压 IPA。工作目录可放到外置缓存；钥匙串仍在内置盘。
    NSURL *tempDir = altsignMakeWorkDirectory();

    NSURL *payloadDir = [tempDir URLByAppendingPathComponent:@"Payload"];

    NSLog(@"[Signer] Extracting IPA: %@", ipaURL.path);

    NSTask *unzipTask = [[NSTask alloc] init];
    unzipTask.launchPath = @"/usr/bin/ditto";
    unzipTask.arguments = @[@"-xk", ipaURL.path, tempDir.path];
    [unzipTask launch];
    [unzipTask waitUntilExit];

    if (unzipTask.terminationStatus != 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-1
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to extract IPA"}]);
        return;
    }

    // 找到 .app bundle
    NSURL *appURL = nil;
    for (NSURL *url in [fm contentsOfDirectoryAtURL:payloadDir
                            includingPropertiesForKeys:nil options:0 error:nil]) {
        if ([url.pathExtension isEqualToString:@"app"]) {
            appURL = url;
            break;
        }
    }
    if (!appURL) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-2
                                       userInfo:@{NSLocalizedDescriptionKey: @"No .app found in IPA"}]);
        return;
    }
    NSLog(@"[Signer] Found app bundle: %@", appURL.lastPathComponent);

    [self signPayloadInTemporaryDirectory:tempDir
                                    appURL:appURL
                      provisioningProfiles:profiles
                                 outputURL:outputURL
                         completionHandler:completion];
}

- (void)signAppAtURL:(NSURL *)sourceAppURL
provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
           outputURL:(NSURL *)outputURL
   completionHandler:(void (^)(BOOL, NSError *))completion
{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:sourceAppURL.path isDirectory:&isDir] || !isDir || ![sourceAppURL.pathExtension isEqualToString:@"app"]) {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-11
                                       userInfo:@{NSLocalizedDescriptionKey: @"Input path is not an .app bundle"}]);
        return;
    }

    NSURL *tempDir = altsignMakeWorkDirectory();
    NSURL *payloadDir = [tempDir URLByAppendingPathComponent:@"Payload"];
    [fm createDirectoryAtURL:payloadDir withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:nil];

    NSURL *appURL = [payloadDir URLByAppendingPathComponent:sourceAppURL.lastPathComponent];
    NSLog(@"[Signer] Copying .app bundle: %@", sourceAppURL.path);

    NSTask *copyTask = [[NSTask alloc] init];
    copyTask.launchPath = @"/usr/bin/ditto";
    copyTask.arguments = @[sourceAppURL.path, appURL.path];
    [copyTask launch];
    [copyTask waitUntilExit];

    if (copyTask.terminationStatus != 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-12
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to copy .app bundle"}]);
        return;
    }

    NSLog(@"[Signer] Found app bundle: %@", appURL.lastPathComponent);
    [self signPayloadInTemporaryDirectory:tempDir
                                    appURL:appURL
                      provisioningProfiles:profiles
                                 outputURL:outputURL
                         completionHandler:completion];
}

- (void)signPayloadInTemporaryDirectory:(NSURL *)tempDir
                                 appURL:(NSURL *)appURL
                   provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
                              outputURL:(NSURL *)outputURL
                      completionHandler:(void (^)(BOOL, NSError *))completion
{
    NSFileManager *fm = [NSFileManager defaultManager];

    // Step 2: 读取主 app 的 Bundle ID 作为 default
    NSDictionary *mainInfo = [NSDictionary dictionaryWithContentsOfURL:[appURL URLByAppendingPathComponent:@"Info.plist"]];
    NSString *defaultBundleID = mainInfo[@"CFBundleIdentifier"];
    if (!defaultBundleID || defaultBundleID.length == 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-10
                                       userInfo:@{NSLocalizedDescriptionKey: @"Main app missing CFBundleIdentifier"}]);
        return;
    }

    // 嵌入 Provisioning Profile + 提取 Entitlements
    NSMutableDictionary<NSString *, NSString *> *entitlementsByPath = [NSMutableDictionary dictionary];

    if (![self prepareAppAtURL:appURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath defaultBundleID:defaultBundleID]) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-10
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to prepare app bundle"}]);
        return;
    }

    if (entitlementsByPath.count == 0) {
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-5
                                       userInfo:@{NSLocalizedDescriptionKey: @"No entitlements extracted"}]);
        return;
    }

    // Step 3: 生成 P12
    NSData *p12Data = [self.certificate p12Data];
    if (!p12Data) {
        emitSignEvent(@"identity", @"mismatch", @"p12");
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-3
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to generate P12"}]);
        return;
    }
    NSLog(@"[Signer] P12 generated: %lu bytes", (unsigned long)p12Data.length);

    // File-based keychains on macOS 15 do not yield a codesign-usable identity.
    // Import an ephemeral identity into the login keychain, sign, then delete it.
    NSString *loginPath = LoginKeychainPath();
    NSURL *p12URL = [tempDir URLByAppendingPathComponent:@"cert.p12"];
    [p12Data writeToURL:p12URL atomically:YES];
    NSString *importOutput = nil;
    int importStatus = [self runTask:@"/usr/bin/security" args:@[@"import", p12URL.path, @"-k", loginPath, @"-P", @"altsign",
                                                @"-T", @"/usr/bin/codesign", @"-T", @"/usr/bin/security"] output:&importOutput];
    BOOL removeIdentityAfter = (importStatus == 0);
    NSString *identity = SHA1HexFromData(self.certificate.data);
    if (identity.length == 0) {
        identity = [self findSigningIdentity:[NSURL fileURLWithPath:loginPath]];
    }
    if (importStatus != 0 && ![[importOutput lowercaseString] containsString:@"already exists"]) {
        emitSignEvent(@"import", @"failed", @"security-import");
        NSLog(@"[Error] Failed to import signing certificate into the login keychain");
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-6
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to import signing certificate"}]);
        return;
    }
    if (!identity) {
        emitSignEvent(@"identity", @"missing", @"find-identity");
        NSLog(@"[Error] No signing identity found after importing the certificate");
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-6
                                       userInfo:@{NSLocalizedDescriptionKey: @"No signing identity found"}]);
        return;
    }
    NSLog(@"[Signer] Identity ready");
    [self ensureWWDRCertificatesInKeychain:loginPath];

    void (^cleanupSigningKeychain)(void) = ^{
        if (removeIdentityAfter && identity.length == 40) {
            [self runTask:@"/usr/bin/security" args:@[@"delete-identity", @"-Z", identity, loginPath]];
        }
        [fm removeItemAtURL:p12URL error:nil];
    };

    // Step 5: 从内到外签名
    NSLog(@"[Signer] Signing binaries...");

    // 递归收集 .app 内所有 .framework / .dylib，按路径深度降序（最深的先签）
    NSMutableArray<NSString *> *signablePaths = [NSMutableArray array];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:appURL
                                  includingPropertiesForKeys:nil
                                                     options:NSDirectoryEnumerationSkipsHiddenFiles
                                                errorHandler:nil];
    for (NSURL *url in enumerator) {
        NSString *ext = url.pathExtension;
        if ([ext isEqualToString:@"framework"] || [ext isEqualToString:@"dylib"]) {
            [signablePaths addObject:url.path];
        }
    }
    [signablePaths sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSUInteger da = [a componentsSeparatedByString:@"/"].count;
        NSUInteger db = [b componentsSeparatedByString:@"/"].count;
        return (da > db) ? NSOrderedAscending : ((da < db) ? NSOrderedDescending : NSOrderedSame);
    }];

    for (NSString *itemPath in signablePaths) {
        NSString *codesignOutput = nil;
        int status = [self codesignPath:itemPath identity:identity entitlements:nil output:&codesignOutput];
        if (status != 0) {
            NSString *reason = CodesignFailureReason(codesignOutput);
            emitSignEvent(@"codesign", @"failed", reason);
            NSLog(@"[Signer] Failed to sign: %@ (exit %d) output=%@", [itemPath lastPathComponent], status, codesignOutput ?: @"");
            cleanupSigningKeychain();
            [fm removeItemAtURL:tempDir error:nil];
            completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-7
                                           userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Failed to sign: %@", itemPath.lastPathComponent]}]);
            return;
        }
        NSLog(@"[Signer] Signed: %@", [itemPath lastPathComponent]);
    }

    // 签名 PlugIns 中的 .appex/.xctest bundle（按路径深度降序，内层先签）
    NSMutableArray<NSString *> *extBinaryPaths = [NSMutableArray array];
    for (NSString *path in entitlementsByPath) {
        NSString *bundlePath = [path stringByDeletingLastPathComponent];
        if ([bundlePath hasSuffix:@".appex"] || [bundlePath hasSuffix:@".xctest"]) {
            [extBinaryPaths addObject:path];
        }
    }
    [extBinaryPaths sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSUInteger da = [a componentsSeparatedByString:@"/"].count;
        NSUInteger db = [b componentsSeparatedByString:@"/"].count;
        return (da > db) ? NSOrderedAscending : ((da < db) ? NSOrderedDescending : NSOrderedSame);
    }];

    for (NSString *path in extBinaryPaths) {
        NSString *bundlePath = [path stringByDeletingLastPathComponent];
        NSURL *entURL = [tempDir URLByAppendingPathComponent:
            [NSString stringWithFormat:@"ent_%@.plist", [[NSUUID UUID] UUIDString]]];
        [entitlementsByPath[path] writeToURL:entURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSString *codesignOutput = nil;
        int status = [self codesignPath:bundlePath identity:identity entitlements:entURL.path output:&codesignOutput];
        if (status != 0) {
            NSString *reason = CodesignFailureReason(codesignOutput);
            emitSignEvent(@"codesign", @"failed", reason);
            NSLog(@"[Signer] Failed to sign extension: %@ (exit %d)", [bundlePath lastPathComponent], status);
            cleanupSigningKeychain();
            [fm removeItemAtURL:tempDir error:nil];
            completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-8
                                           userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Failed to sign extension: %@", bundlePath.lastPathComponent]}]);
            return;
        }
        NSLog(@"[Signer] Signed nested: %@", [bundlePath lastPathComponent]);
    }

    // 签名主 app bundle — 从 entitlementsByPath 中找到主 app 二进制对应的 entitlements
    NSString *mainPath = appURL.path;
    NSString *mainExe = mainInfo[@"CFBundleExecutable"] ?: @"";
    NSString *mainEnt = entitlementsByPath[[mainPath stringByAppendingPathComponent:mainExe]];
    if (!mainEnt) {
        // fallback: 单一 profile 场景（CLI 默认流程），取唯一条目
        mainEnt = entitlementsByPath.allValues.firstObject;
    }
    NSURL *mainEntURL = [tempDir URLByAppendingPathComponent:@"ent_main.plist"];
    [mainEnt writeToURL:mainEntURL atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSString *codesignOutput = nil;
    int status = [self codesignPath:mainPath identity:identity entitlements:mainEntURL.path output:&codesignOutput];
    if (status != 0) {
        NSString *reason = CodesignFailureReason(codesignOutput);
        emitSignEvent(@"codesign", @"failed", reason);
        NSLog(@"[Signer] Failed to sign main app bundle (exit %d)", status);
        cleanupSigningKeychain();
        [fm removeItemAtURL:tempDir error:nil];
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-9
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to sign main app bundle"}]);
        return;
    }
    NSLog(@"[Signer] Signed app bundle");

    cleanupSigningKeychain();

    // Step 6: 重新打包
    NSLog(@"[Signer] Repacking IPA...");
    [fm removeItemAtURL:outputURL error:nil];

    NSTask *zipTask = [[NSTask alloc] init];
    zipTask.launchPath = @"/usr/bin/zip";
    zipTask.arguments = @[@"-rq", outputURL.path, @"Payload"];
    zipTask.currentDirectoryURL = tempDir;
    [zipTask launch];
    [zipTask waitUntilExit];

    [fm removeItemAtURL:tempDir error:nil];

    if (zipTask.terminationStatus == 0) {
        NSLog(@"[Signer] Successfully signed IPA: %@", outputURL.path);
        completion(YES, nil);
    } else {
        completion(NO, [NSError errorWithDomain:@"com.altsign.signer" code:-4
                                       userInfo:@{NSLocalizedDescriptionKey: @"Failed to repack IPA"}]);
    }
}

#pragma mark - Helpers

- (void)ensureWWDRCertificatesInKeychain:(NSString *)loginPath {
    if (loginPath.length == 0) return;
    NSString *exe = [[NSProcessInfo processInfo] arguments].firstObject;
    NSString *dir = [[exe stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"wwdr"];
    NSArray<NSString *> *names = @[@"AppleWWDRCA.cer", @"AppleWWDRCAG3.cer", @"AppleWWDRCAG4.cer"];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *name in names) {
        NSString *path = [dir stringByAppendingPathComponent:name];
        if (![fm fileExistsAtPath:path]) continue;
        [self runTask:@"/usr/bin/security" args:@[@"add-certificates", @"-k", loginPath, path]];
    }
}

- (int)codesignPath:(NSString *)path identity:(NSString *)identity entitlements:(NSString *)entitlements output:(NSString **)outOutput {
    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithObjects:@"--force", @"--sign", identity, nil];
    if (entitlements.length > 0) {
        [args addObject:@"--entitlements"];
        [args addObject:entitlements];
        [args addObject:@"--generate-entitlement-der"];
    }
    [args addObject:path];
    return [self runTask:@"/usr/bin/codesign" args:args output:outOutput];
}

- (NSString *)findSigningIdentity:(NSURL *)keychainURL {
    NSString *output = nil;
    [self runTask:@"/usr/bin/security" args:@[@"find-identity", @"-v", @"-p", @"codesigning", keychainURL.path] output:&output];
    NSString *fingerprint = FingerprintFromIdentityOutput(output);
    if (fingerprint.length > 0) return fingerprint;
    output = nil;
    [self runTask:@"/usr/bin/security" args:@[@"find-identity", @"-v", keychainURL.path] output:&output];
    return FingerprintFromIdentityOutput(output);
}

- (int)runTask:(NSString *)launchPath args:(NSArray *)args {
    return [self runTask:launchPath args:args output:nil];
}

- (int)runTask:(NSString *)launchPath args:(NSArray *)args output:(NSString **)outOutput {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = launchPath;
    task.arguments = args;
    NSPipe *outPipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    task.standardOutput = outPipe;
    task.standardError = errPipe;
    [task launch];
    NSData *outData = [[outPipe fileHandleForReading] readDataToEndOfFile];
    NSData *errData = [[errPipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];
    NSMutableString *combined = [NSMutableString string];
    NSString *stdoutText = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding];
    NSString *stderrText = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding];
    if (stdoutText.length > 0) [combined appendString:stdoutText];
    if (stderrText.length > 0) {
        if (combined.length > 0) [combined appendString:@"\n"];
        [combined appendString:stderrText];
    }
    if (outOutput) *outOutput = combined;
    if (task.terminationStatus != 0 && combined.length > 0) {
        NSLog(@"[Signer] %@ exited %d", launchPath.lastPathComponent, task.terminationStatus);
    }
    return task.terminationStatus;
}

#pragma mark - Prepare App

- (BOOL)prepareAppAtURL:(NSURL *)appURL
   provisioningProfiles:(NSArray<ALTProvisioningProfile *> *)profiles
    entitlementsByPath:(NSMutableDictionary *)entitlementsByPath
         defaultBundleID:(NSString *)defaultBundleID
{
    NSURL *infoPlistURL = [appURL URLByAppendingPathComponent:@"Info.plist"];
    NSMutableDictionary *infoPlist = [[NSDictionary dictionaryWithContentsOfURL:infoPlistURL] mutableCopy];
    NSString *originalBundleID = infoPlist[@"CFBundleIdentifier"];
    if (!originalBundleID || originalBundleID.length == 0) {
        NSLog(@"[Signer] Error: Missing CFBundleIdentifier in %@", appURL.lastPathComponent);
        return NO;
    }

    NSString *bundleID = originalBundleID;

    NSString *executable = infoPlist[@"CFBundleExecutable"] ?: @"";

    ALTProvisioningProfile *matchedProfile = nil;
    for (ALTProvisioningProfile *profile in profiles) {
        if ([profile.bundleIdentifier isEqualToString:bundleID]) {
            matchedProfile = profile;
            break;
        }
    }
    if (!matchedProfile && profiles.count > 0) {
        for (ALTProvisioningProfile *profile in profiles) {
            if ([profile.bundleIdentifier hasSuffix:@"*"]) {
                matchedProfile = profile;
                break;
            }
        }
    }
    if (!matchedProfile) {
        NSLog(@"[Signer] Error: No profile found for %@", bundleID);
        return NO;
    }

    NSURL *profileURL = [appURL URLByAppendingPathComponent:@"embedded.mobileprovision"];
    [matchedProfile.data writeToURL:profileURL atomically:YES];

    NSDictionary *entitlements = matchedProfile.entitlements;
    if (!entitlements && matchedProfile.data) {
        NSString *profileStr = [[NSString alloc] initWithData:matchedProfile.data
                                                     encoding:NSASCIIStringEncoding];
        NSRange plistStart = [profileStr rangeOfString:@"<?xml"];
        NSRange plistEnd = [profileStr rangeOfString:@"</plist>"];
        if (plistStart.location != NSNotFound && plistEnd.location != NSNotFound) {
            NSRange range = NSMakeRange(plistStart.location,
                plistEnd.location + plistEnd.length - plistStart.location);
            NSDictionary *plist = [NSPropertyListSerialization
                propertyListWithData:[[profileStr substringWithRange:range]
                                    dataUsingEncoding:NSUTF8StringEncoding]
                options:0 format:nil error:nil];
            entitlements = plist[@"Entitlements"];
        }
    }

    if (entitlements) {
        NSData *entData = [NSPropertyListSerialization
            dataWithPropertyList:entitlements format:NSPropertyListXMLFormat_v1_0
                        options:0 error:nil];
        NSString *entString = [[NSString alloc] initWithData:entData encoding:NSUTF8StringEncoding];
        NSURL *binaryURL = [appURL URLByAppendingPathComponent:executable];
        entitlementsByPath[binaryURL.path] = entString;
    } else {
        NSLog(@"[Signer] Warning: No entitlements found for %@", bundleID);
    }

    NSURL *nestedPlugInsURL = [appURL URLByAppendingPathComponent:@"PlugIns"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:nestedPlugInsURL.path]) {
        for (NSURL *extURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:nestedPlugInsURL
                                includingPropertiesForKeys:nil options:0 error:nil]) {
            if ([extURL.pathExtension isEqualToString:@"appex"] ||
                [extURL.pathExtension isEqualToString:@"xctest"]) {
                if (![self prepareAppAtURL:extURL provisioningProfiles:profiles entitlementsByPath:entitlementsByPath defaultBundleID:defaultBundleID]) {
                    return NO;
                }
            }
        }
    }
    return YES;
}

@end
