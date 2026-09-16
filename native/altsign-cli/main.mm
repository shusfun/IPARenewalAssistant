//
//  main.mm
//  AltSign CLI
//
//  macOS 命令行自签名工具
//  Usage:
//    altsign-cli list   --apple-id <email>
//    altsign-cli sign   --udid <udid> --ipa <path.ipa|path.app> [--output <path.ipa>]
//    altsign-cli sign   --udid <udid> --app <path.app> [--output <path.ipa>]
//
//  首次认证的密码与 2FA 都从标准输入读取。

#import <Foundation/Foundation.h>
#import "anisette.h"
#import "srp_auth.h"
#import "apple_api.h"
#import "certificate_request.h"
#import "signer.h"
#import "keychain.h"
#import <Security/Security.h>

#include <readpassphrase.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// ============================================================
// 辅助函数
// ============================================================

static NSString *const kCertificateKeychainService = @"com.shus.iparenewalassistant.certificate-key";
static NSString *const kCertificateKeychainLabel = @"IPARenewalAssistant Certificate Key";

static void emitCertificateEvent(NSString *action, NSString *reason) {
    fprintf(stderr, "EVENT:certificate action=%s reason=%s\n",
            (action.length > 0 ? action.UTF8String : "unknown"),
            (reason.length > 0 ? reason.UTF8String : "unknown"));
    fflush(stderr);
}

static void saveCertKey(NSString *certID, NSData *privateKey) {
    if (certID.length == 0 || privateKey.length == 0) return;
    ALTKeychainSaveData(kCertificateKeychainService, certID, privateKey, kCertificateKeychainLabel);
    NSString *normalized = ALTNormalizedCertificateSerial(certID);
    if (normalized.length > 0 && ![normalized isEqualToString:certID]) {
        ALTKeychainSaveData(kCertificateKeychainService, normalized, privateKey, kCertificateKeychainLabel);
    }
}

static ALTKeychainStatus loadCertKey(NSString *certID, NSData **outKey) {
    if (outKey) *outKey = nil;
    if (certID.length == 0) return ALTKeychainStatusNotFound;
    ALTKeychainStatus status = ALTKeychainLoadData(kCertificateKeychainService, certID, YES, outKey);
    if (status != ALTKeychainStatusNotFound) return status;
    NSString *normalized = ALTNormalizedCertificateSerial(certID);
    if (normalized.length == 0 || [normalized isEqualToString:certID]) return status;
    return ALTKeychainLoadData(kCertificateKeychainService, normalized, YES, outKey);
}

static void writeJSONResult(NSDictionary *object) {
    if (!object) return;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:0 error:&error];
    if (!data) {
        fprintf(stderr, "Error: failed to encode JSON result: %s\n",
                error.localizedDescription.UTF8String ?: "unknown");
        return;
    }
    fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static BOOL certificateCreateIsQuotaOrPermissionError(NSError *error) {
    if (!error) return NO;
    if (error.code == 403 || error.code == 409) return YES;
    NSString *reason = error.localizedDescription.lowercaseString ?: @"";
    return [reason containsString:@"maximum"] ||
           [reason containsString:@"limit"] ||
           [reason containsString:@"already"] ||
           [reason containsString:@"permission"] ||
           [reason containsString:@"not allowed"] ||
           [reason containsString:@"quota"];
}

// ============================================================
// Capability 名称 → Feature ID 映射
// ============================================================

static NSDictionary<NSString *, NSString *> *capabilityFeatureMap(void) {
    return @{
        @"app-groups":         @"APG3427HIY",
        @"healthkit":          @"HK421J6T7P",
        @"push":               @"IAD53UNK2F",
        @"sign-in-with-apple": @"LPLF93JG7M",
        @"associated-domains": @"SKC3T5S89Y",
        @"vpn":                @"V66P55NK2I",
        @"external-accessory": @"WC421J6T7P",
        @"gamecenter":         @"gameCenter",
    };
}

static void printCapabilities(void) {
    fprintf(stderr,
        "可用的 --entitlement 名称:\n"
        "  app-groups           应用组 (com.apple.security.application-groups)\n"
        "  healthkit            HealthKit\n"
        "  push                 远程推送\n"
        "  sign-in-with-apple   Apple 登录\n"
        "  associated-domains   关联域名\n"
        "  external-accessory   无线配件配置\n"
        "  gamecenter           游戏中心\n"
        "\n"
        "需要付费开发者账号 ($99/年):\n"
        "  vpn                  网络扩展 / VPN (Network Extension)\n"
        "\n"
    );
}

static void printUsage(void) {
    fprintf(stderr,
        "AltSign CLI — macOS IPA/.app 自签名工具\n"
        "\n"
        "用法:\n"
        "  altsign-cli list     --apple-id <email>\n"
        "  altsign-cli diagnose\n"
        "  altsign-cli session\n"
        "  altsign-cli sign     --team-id <id> --udid <udid> --ipa <file.ipa|file.app> [--output <file.ipa>]\n"
        "  altsign-cli sign     --team-id <id> --udid <udid> --app <file.app> [--output <file.ipa>]\n"
        "\n"
        "命令:\n"
        "  list     独立登录并在 stdout 输出全部开发团队 JSON\n"
        "  diagnose 无凭据网络对照（最小 GET / 客户端标识 / Anisette / 出口）\n"
        "  session  核验本机缓存会话，不读取密码\n"
        "  sign     使用缓存 session 与指定团队签名 IPA/.app\n"
        "\n"
        "认证输入:\n"
        "  list --apple-id 从标准输入读取密码和 2FA；终端密码不回显\n"
        "\n"
        "选项:\n"
        "  --apple-id      list 要认证的 Apple ID 邮箱\n"
        "  --team-id       sign 必须指定的开发团队 ID\n"
        "  --udid          iOS 设备 UDID\n"
        "  --ipa           待签名的 IPA 或 .app 路径\n"
        "  --app           待签名的 .app 路径\n"
        "  --output        输出签名后的 IPA 路径 (默认在原文件名加 _signed)\n"
        "  --entitlement   启用的 capabilities，逗号分隔 (如 healthkit,app-groups)\n"
        "  --reissue-certificate  用户确认后：撤销本机无私钥的开发证书并重新申请\n"
        "  --verbose       打印完整日志（默认截断大响应）\n"
        "\n"
    );
    printCapabilities();
}

static NSString * _Nullable getArg(NSArray *args, NSString *flag) {
    NSUInteger idx = NSNotFound;
    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:flag]) {
            idx = i;
        }
    }
    if (idx != NSNotFound && idx + 1 < args.count) {
        return args[idx + 1];
    }
    return nil;
}

static BOOL hasFlag(NSArray *args, NSString *flag) {
    return [args containsObject:flag];
}

static BOOL validateCommandOptions(NSArray<NSString *> *args,
                                   NSString *command,
                                   NSString **errorMessage) {
    NSSet<NSString *> *valueOptions = [NSSet set];
    if ([command isEqualToString:@"list"]) {
        valueOptions = [NSSet setWithArray:@[@"--apple-id"]];
    } else if ([command isEqualToString:@"sign"]) {
        valueOptions = [NSSet setWithArray:@[
            @"--udid", @"--ipa", @"--app", @"--output", @"--entitlement", @"--team-id"
        ]];
    } else if ([command isEqualToString:@"session"] || [command isEqualToString:@"diagnose"]) {
        valueOptions = [NSSet set];
    } else {
        valueOptions = [NSSet set];
    }
    NSMutableSet<NSString *> *flagOptions = [NSMutableSet setWithObject:@"--verbose"];
    if ([command isEqualToString:@"sign"]) {
        [flagOptions addObject:@"--reissue-certificate"];
    }
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (NSUInteger index = 2; index < args.count; index += 1) {
        NSString *argument = args[index];
        BOOL takesValue = [valueOptions containsObject:argument];
        if (!takesValue && ![flagOptions containsObject:argument]) {
            if (errorMessage != NULL) {
                *errorMessage = [NSString stringWithFormat:
                    @"unknown option for %@: %@", command, argument];
            }
            return NO;
        }
        if ([seen containsObject:argument]) {
            if (errorMessage != NULL) {
                *errorMessage = [NSString stringWithFormat:
                    @"duplicate option: %@", argument];
            }
            return NO;
        }
        [seen addObject:argument];
        if (takesValue) {
            if (index + 1 >= args.count ||
                [args[index + 1] hasPrefix:@"--"]) {
                if (errorMessage != NULL) {
                    *errorMessage = [NSString stringWithFormat:
                        @"%@ requires a value", argument];
                }
                return NO;
            }
            index += 1;
        }
    }
    return YES;
}

static BOOL isAppBundlePath(NSString *path) {
    return [path.pathExtension.lowercaseString isEqualToString:@"app"];
}

static BOOL isIPAPath(NSString *path) {
    return [path.pathExtension.lowercaseString isEqualToString:@"ipa"];
}

static NSArray<NSString *> * _Nullable extractBundleIDsFromAppBundle(NSString *appPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:appPath isDirectory:&isDir] || !isDir || !isAppBundlePath(appPath)) {
        return nil;
    }

    NSMutableArray<NSString *> *bundleIDs = [NSMutableArray array];
    void (^appendBundleID)(NSURL *) = ^(NSURL *url) {
        NSURL *infoPlistURL = [url URLByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL];
        NSString *bundleID = infoPlist[@"CFBundleIdentifier"];
        if (bundleID.length > 0) [bundleIDs addObject:bundleID];
    };

    NSURL *appURL = [NSURL fileURLWithPath:appPath];
    appendBundleID(appURL);

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:appURL
                                 includingPropertiesForKeys:nil
                                                    options:NSDirectoryEnumerationSkipsHiddenFiles
                                               errorHandler:nil];
    for (NSURL *url in enumerator) {
        NSString *ext = url.pathExtension;
        if ([ext isEqualToString:@"appex"] || [ext isEqualToString:@"xctest"]) {
            appendBundleID(url);
        }
    }

    return bundleIDs.count > 0 ? bundleIDs : nil;
}

static NSArray<NSString *> * _Nullable extractBundleIDsFromIPA(NSString *ipaPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *tempDir = [fm.temporaryDirectory URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    [fm createDirectoryAtURL:tempDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSTask *unzipTask = [[NSTask alloc] init];
    unzipTask.launchPath = @"/usr/bin/ditto";
    unzipTask.arguments = @[@"-xk", ipaPath, tempDir.path];
    [unzipTask launch];
    [unzipTask waitUntilExit];

    if (unzipTask.terminationStatus != 0) {
        [fm removeItemAtURL:tempDir error:nil];
        return nil;
    }

    NSURL *payloadDir = [tempDir URLByAppendingPathComponent:@"Payload"];
    NSMutableArray<NSString *> *bundleIDs = [NSMutableArray array];

    void (^collectBundleIDs)(NSURL *) = ^(NSURL *dir) {
        NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:dir
                                     includingPropertiesForKeys:nil
                                                        options:NSDirectoryEnumerationSkipsHiddenFiles
                                                   errorHandler:nil];
        for (NSURL *url in enumerator) {
            NSString *ext = url.pathExtension;
            if ([ext isEqualToString:@"app"] || [ext isEqualToString:@"appex"] || [ext isEqualToString:@"xctest"]) {
                NSURL *infoPlistURL = [url URLByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfURL:infoPlistURL];
                NSString *bundleID = infoPlist[@"CFBundleIdentifier"];
                if (bundleID && bundleID.length > 0) {
                    [bundleIDs addObject:bundleID];
                }
            }
        }
    };
    collectBundleIDs(payloadDir);

    [fm removeItemAtURL:tempDir error:nil];
    return bundleIDs.count > 0 ? bundleIDs : nil;
}

// ============================================================
// 认证（含 session 复用 + 2FA）
// ============================================================

static NSError *AltSignCLIError(NSString *message) {
    return [NSError errorWithDomain:@"com.altsign.cli"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

static void clearSensitiveBuffer(char *buffer, size_t length) {
    volatile char *cursor = buffer;
    while (length-- > 0) {
        *cursor++ = 0;
    }
}

static NSString * _Nullable readPasswordFromStandardInput(
    NSString *appleID,
    NSError **error
) {
    char password[4096] = {0};
    NSString *prompt = [NSString stringWithFormat:
        @"Apple ID password for %@: ", appleID];
    int flags = isatty(STDIN_FILENO) ? RPP_REQUIRE_TTY : RPP_STDIN;
    errno = 0;
    char *result = readpassphrase(
        prompt.UTF8String,
        password,
        sizeof(password),
        flags
    );
    if (result == NULL) {
        if (error != NULL) {
            NSString *reason = errno == 0
                ? @"password was not provided"
                : [NSString stringWithFormat:
                    @"could not read the password from standard input: %s",
                    strerror(errno)];
            *error = AltSignCLIError(reason);
        }
        clearSensitiveBuffer(password, sizeof(password));
        return nil;
    }
    NSString *value = [[NSString alloc] initWithUTF8String:password];
    clearSensitiveBuffer(password, sizeof(password));
    if (value.length == 0 && error != NULL) {
        *error = AltSignCLIError(@"password was not provided");
    }
    return value.length > 0 ? value : nil;
}

static NSString * _Nullable readVerificationCodeFromStandardInput(
    void (^resend)(void (^completion)(NSError * _Nullable error))
) {
    fprintf(stderr, "EVENT:challenge\n");
    fprintf(stderr, "2FA verification required. Enter code: ");
    fflush(stderr);
    while (true) {
        char buffer[64] = {0};
        char *result = fgets(buffer, sizeof(buffer), stdin);
        if (result == NULL) return nil;
        NSString *code = [[NSString alloc] initWithUTF8String:buffer];
        NSString *trimmed = [code stringByTrimmingCharactersInSet:
            NSCharacterSet.whitespaceAndNewlineCharacterSet];
        clearSensitiveBuffer(buffer, sizeof(buffer));
        if ([trimmed isEqualToString:@"resend"]) {
            dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
            __block NSError *resendError = nil;
            resend(^(NSError *error) { resendError = error; dispatch_semaphore_signal(semaphore); });
            long waitResult = dispatch_semaphore_wait(
                semaphore,
                dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)
            );
            if (waitResult != 0) {
                fprintf(stderr, "EVENT:resend-result:error:request timed out\n");
            } else if (resendError) {
                fprintf(stderr, "EVENT:resend-result:error:%s\n", resendError.localizedDescription.UTF8String);
            } else {
                fprintf(stderr, "EVENT:resend-result:ok\n");
            }
            fflush(stderr);
            continue;
        }
        return trimmed.length > 0 ? trimmed : nil;
    }
}

static void authenticateWithAppleID(NSString *appleID, NSString *password,
                                    void (^completion)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))
{
    [ALTAnisetteData fetchAnisetteDataWithCompletion:^(ALTAnisetteData *anisetteData, NSError *error) {
        if (error || !anisetteData) {
            completion(nil, nil, error ?: [NSError errorWithDomain:@"com.altsign" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Failed to fetch Anisette data"}]);
            return;
        }
        if (anisetteData.machineID.length == 0 || anisetteData.oneTimePassword.length == 0) {
            completion(nil, nil, [NSError errorWithDomain:@"com.altsign" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"无法获取本机 Apple 登录凭证"}]);
            return;
        }

        NSString *cachedAppleID = nil;
        ALTAppleAPISession *cachedSession =
            [ALTAppleAPISession loadSession:&cachedAppleID];
        if ([cachedAppleID isEqualToString:appleID] &&
            cachedSession && !cachedSession.isExpired) {
            NSLog(@"[Auth] Reusing cached session (expires: %@)", cachedSession.expirationDate);
            cachedSession.anisetteData = anisetteData;
            [cachedSession saveForAppleID:appleID];
            ALTAccount *account = [[ALTAccount alloc] init];
            account.appleID = appleID;
            account.identifier = cachedSession.dsid;
            completion(account, cachedSession, nil);
            return;
        }

        NSLog(@"[Auth] Cached session missing or expired, performing SRP login...");

        ALTVerificationHandler verificationHandler = ^(
            void (^callback)(NSString * _Nullable code),
            void (^resend)(void (^completion)(NSError * _Nullable error))
        ) {
            callback(readVerificationCodeFromStandardInput(resend));
        };

        [ALTSRPAuthenticator authenticateWithAppleID:appleID
                                            password:password
                                        anisetteData:anisetteData
                                   verificationHandler:verificationHandler
                                   completionHandler:completion];
    }];
}

// ============================================================
// 核心流程
// ============================================================

static BOOL performSign(NSString *appleID, NSString *password,
                        NSString *teamID, NSString *udid, NSString *inputPath, NSString *outputPath,
                        NSArray<NSString *> *entitlementNames, BOOL reissueCertificate)
{
    BOOL inputIsApp = isAppBundlePath(inputPath);
    if (!inputIsApp && !isIPAPath(inputPath)) {
        NSLog(@"[Error] Input must be an .ipa file or .app bundle: %@", inputPath);
        return NO;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL succeeded = NO;

    NSLog(@"========================================");
    NSLog(@" AltSign CLI — IPA/.app 自签名工具");
    NSLog(@"========================================");
    NSLog(@" Apple ID:  %@", appleID);
    NSLog(@" Team ID:   %@", teamID);
    NSLog(@" UDID:      %@", udid);
    NSLog(@" Input:     %@", inputPath);
    NSLog(@" Output:    %@", outputPath);
    NSLog(@"========================================");

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            NSLog(@"[Error] Authentication failed: %@", error);
            dispatch_semaphore_signal(sem);
            return;
        }
        NSLog(@"[Step 1] Login successful! DSID: %@", account.identifier);

        ALTAppleAPI *api = [ALTAppleAPI sharedAPI];

        // Step 2: 获取团队
        NSLog(@"[Step 2] Fetching teams...");
        [api fetchTeamsForAccount:account session:session completionHandler:^(NSArray<ALTTeam *> *teams, NSError *error) {
            if (error || teams.count == 0) {
                NSLog(@"[Error] No teams found: %@", error);
                dispatch_semaphore_signal(sem);
                return;
            }

            ALTTeam *team = nil;
            for (ALTTeam *candidate in teams) {
                if ([candidate.identifier isEqualToString:teamID]) {
                    team = candidate;
                    break;
                }
            }
            if (!team) {
                NSLog(@"[Error] Selected team %@ was not in the account team list", teamID);
                dispatch_semaphore_signal(sem);
                return;
            }
            NSLog(@"[Step 2] Using team: %@ (%@) type=%@", team.name, team.identifier, team.type);

            // Step 3: 获取证书
            NSLog(@"[Step 3] Fetching certificates...");
            [api fetchCertificatesForTeam:team session:session completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {
                if (error) {
                    NSLog(@"[Error] Failed to fetch certificates: %@", error);
                    dispatch_semaphore_signal(sem);
                    return;
                }

                void (^continueWithCert)(ALTCertificate *) = ^(ALTCertificate *cert) {
                    // Step 4: 注册设备
                    NSLog(@"[Step 4] Registering device: %@", udid);
                    [api registerDeviceWithName:@"AltSign Device" identifier:udid team:team session:session completionHandler:^(ALTDevice *device, NSError *error) {
                        if (error || device == nil) {
                            NSLog(@"[Error] Failed to register device: %@", error);
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        NSLog(@"[Step 4] Device registered or already exists");

                        // Step 5: 提取所有需要签名的 bundle ID
                        NSArray<NSString *> *bundleIDs = inputIsApp ? extractBundleIDsFromAppBundle(inputPath) : extractBundleIDsFromIPA(inputPath);
                        if (!bundleIDs || bundleIDs.count == 0) {
                            NSLog(@"[Error] Failed to read bundle IDs from input");
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        NSLog(@"[Step 5] Bundle IDs to resolve: %@", [bundleIDs componentsJoinedByString:@", "]);

                        // Step 6: 获取已有 App ID 列表，然后串行创建缺失的 App ID 并下载 Profile
                        [api fetchAppIDsForTeam:team session:session completionHandler:^(NSArray<ALTAppID *> *appIDs, NSError *error) {
                            if (error) {
                                NSLog(@"[Error] fetchAppIDs failed: %@", error);
                                dispatch_semaphore_signal(sem);
                                return;
                            }

                            NSMutableArray<ALTProvisioningProfile *> *profiles = [NSMutableArray array];
                            dispatch_queue_t serialQueue = dispatch_queue_create("com.altsign.profile", DISPATCH_QUEUE_SERIAL);

                            void (^finishWithError)(NSString *) = ^(NSString *reason) {
                                NSLog(@"[Error] %@", reason);
                                dispatch_semaphore_signal(sem);
                            };

                            void (^startSigning)(void) = ^{
                                NSLog(@"[Step 7] Signing %@...", inputIsApp ? @".app" : @"IPA");
                                ALTSigner *signer = [[ALTSigner alloc] initWithCertificate:cert];
                                void (^completion)(BOOL, NSError *) = ^(BOOL success, NSError *error) {
                                    if (success) {
                                        NSLog(@"✅ [Done] IPA signed successfully!");
                                        NSLog(@"   Output: %@", outputPath);
                                        succeeded = YES;
                                    } else {
                                        NSLog(@"❌ [Error] Signing failed: %@", error);
                                    }
                                    dispatch_semaphore_signal(sem);
                                };
                                if (inputIsApp) {
                                    [signer signAppAtURL:[NSURL fileURLWithPath:inputPath]
                                     provisioningProfiles:profiles
                                                outputURL:[NSURL fileURLWithPath:outputPath]
                                        completionHandler:completion];
                                } else {
                                    [signer signIPAAtURL:[NSURL fileURLWithPath:inputPath]
                                     provisioningProfiles:profiles
                                                outputURL:[NSURL fileURLWithPath:outputPath]
                                        completionHandler:completion];
                                }
                            };

                            // 串行处理每个 Bundle ID 的 App ID + Profile（避免主线程死锁）
                            NSMutableArray<NSString *> *remainingBundleIDs = [bundleIDs mutableCopy];
                            __block void (^processNext)(void) = nil;
                            processNext = ^{
                                if (remainingBundleIDs.count == 0) {
                                    if (profiles.count != bundleIDs.count) {
                                        finishWithError(@"Failed to resolve all provisioning profiles");
                                    } else {
                                        startSigning();
                                    }
                                    processNext = nil; // 打破 retain cycle
                                    return;
                                }

                                NSString *bundleID = remainingBundleIDs.firstObject;
                                [remainingBundleIDs removeObjectAtIndex:0];

                                ALTAppID *appID = nil;
                                for (ALTAppID *aid in appIDs) {
                                    if ([aid.bundleIdentifier isEqualToString:bundleID]) { appID = aid; break; }
                                }

                                void (^afterAppID)(ALTAppID *) = ^(ALTAppID *resolvedAppID) {
                                    // 如果指定了 --entitlement，先启用对应的 capabilities
                                    void (^fetchProfile)(ALTAppID *) = ^(ALTAppID *finalAppID) {
                                        [api fetchProvisioningProfileForAppID:finalAppID team:team session:session completionHandler:^(ALTProvisioningProfile *profile, NSError *error) {
                                            if (error || !profile) {
                                                finishWithError([NSString stringWithFormat:@"Failed to fetch profile for %@: %@", bundleID, error]);
                                                processNext = nil;
                                                return;
                                            }
                                            NSLog(@"[Step 6] Profile acquired for %@: %@ (expires: %@)", bundleID, profile.identifier, profile.expirationDate);
                                            [profiles addObject:profile];
                                            dispatch_async(serialQueue, processNext);
                                        }];
                                    };

                                    if (entitlementNames.count > 0) {
                                        // 构建 features 字典
                                        NSDictionary *map = capabilityFeatureMap();
                                        NSMutableDictionary *features = [NSMutableDictionary dictionary];
                                        for (NSString *name in entitlementNames) {
                                            NSString *featureID = map[name.lowercaseString];
                                            if (featureID) {
                                                features[featureID] = @"1";
                                            }
                                        }
                                        if (features.count > 0) {
                                            NSLog(@"[Step 5] Enabling capabilities: %@", entitlementNames);
                                            [api updateAppID:resolvedAppID features:features team:team session:session completionHandler:^(ALTAppID *updated, NSError *error) {
                                                if (error) {
                                                    NSLog(@"[Warning] Failed to enable capabilities: %@", error.localizedDescription);
                                                }
                                                fetchProfile(updated ?: resolvedAppID);
                                            }];
                                        } else {
                                            fetchProfile(resolvedAppID);
                                        }
                                    } else {
                                        fetchProfile(resolvedAppID);
                                    }
                                };

                                if (appID) {
                                    NSLog(@"[Step 5] Reusing existing App ID: %@", appID.bundleIdentifier);
                                    afterAppID(appID);
                                } else {
                                    NSLog(@"[Step 5] Creating App ID: %@", bundleID);
                                    [api addAppIDWithName:@"AltSign App" bundleIdentifier:bundleID team:team session:session completionHandler:^(ALTAppID *newAppID, NSError *error) {
                                        if (error || !newAppID) {
                                            finishWithError([NSString stringWithFormat:@"Failed to create App ID %@: %@", bundleID, error]);
                                            processNext = nil;
                                            return;
                                        }
                                        afterAppID(newAppID);
                                    }];
                                }
                            };

                            dispatch_async(serialQueue, processNext);
                        }];
                    }];
                };

                void (^createNewCert)(void) = ^{
                    NSLog(@"[Step 3] Creating new certificate...");
                    ALTCertificateRequest *certReq = [[ALTCertificateRequest alloc] init];
                    if (!certReq) {
                        NSLog(@"[Error] Failed to generate certificate request");
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    [api submitCertificateRequest:certReq.data team:team session:session completionHandler:^(ALTCertificate *cert, NSError *error) {
                        if (error || !cert) {
                            NSString *serial = error.userInfo[@"serialNum"];
                            if (serial.length > 0) saveCertKey(serial, certReq.privateKey);
                            if (certificateCreateIsQuotaOrPermissionError(error)) {
                                emitCertificateEvent(@"create-failed", @"quota-or-existing");
                                NSLog(@"[Error] Certificate quota or permission denied: %@. Existing certificates were not revoked, and no further certificate request will be submitted.", error.localizedDescription);
                            } else {
                                emitCertificateEvent(@"create-failed", @"request-rejected");
                                NSLog(@"[Error] Failed to create certificate: %@", error);
                            }
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        cert.privateKey = certReq.privateKey;
                        saveCertKey(cert.identifier, cert.privateKey);
                        saveCertKey(cert.serialNumber, cert.privateKey);
                        NSLog(@"[Step 3] Certificate created: %@", cert.identifier);
                        continueWithCert(cert);
                    }];
                };

                ALTCertificate *reusable = nil;
                NSData *cachedKey = nil;
                ALTKeychainStatus keyStatus = ALTKeychainStatusNotFound;
                for (ALTCertificate *cert in certs) {
                    NSLog(@"[Step 3] portal cert id=%@ serial=%@ hasData=%d", cert.identifier ?: @"", cert.serialNumber ?: @"", cert.data != nil);
                    cachedKey = nil;
                    keyStatus = loadCertKey(cert.identifier, &cachedKey);
                    if (keyStatus == ALTKeychainStatusDenied || keyStatus == ALTKeychainStatusUnavailable) {
                        break;
                    }
                    if (!cachedKey) {
                        keyStatus = loadCertKey(cert.serialNumber, &cachedKey);
                    }
                    if (keyStatus == ALTKeychainStatusDenied || keyStatus == ALTKeychainStatusUnavailable) {
                        break;
                    }
                    if (!cachedKey) continue;
                    cert.privateKey = cachedKey;
                    reusable = cert;
                    emitCertificateEvent(@"reuse", @"app-keychain");
                    NSLog(@"[Step 3] Reusing certificate with local private key: %@", cert.identifier);
                    break;
                }
                if (keyStatus == ALTKeychainStatusDenied || keyStatus == ALTKeychainStatusUnavailable || ALTKeychainAccessWasDenied()) {
                    ALTKeychainEmitEvent(@"certificate-key", ALTKeychainAccessWasDenied() ? ALTKeychainStatusDenied : keyStatus);
                    NSLog(@"[Error] Keychain access was denied or unavailable while reading the certificate private key. Existing certificates were not revoked, and no new certificate request will be submitted.");
                    dispatch_semaphore_signal(sem);
                    return;
                }
                if (!reusable) {
                    for (ALTCertificate *cert in certs) {
                        NSData *systemKey = ALTCopyPrivateKeyFromSystemKeychain(cert);
                        if (ALTKeychainAccessWasDenied()) {
                            ALTKeychainEmitEvent(@"identity", ALTKeychainStatusDenied);
                            NSLog(@"[Error] Keychain access was denied while reading a signing identity. Existing certificates were not revoked, and no new certificate request will be submitted.");
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        if (!systemKey) continue;
                        cert.privateKey = systemKey;
                        saveCertKey(cert.identifier, systemKey);
                        saveCertKey(cert.serialNumber, systemKey);
                        reusable = cert;
                        emitCertificateEvent(@"reuse", @"system-identity");
                        NSLog(@"[Step 3] Found matching private key in the system keychain");
                        break;
                    }
                }
                if (!reusable) {
                    ALTCertificate *localCert = nil;
                    NSData *localKey = ALTCopyTeamIdentityFromSystemKeychain(team.identifier, &localCert);
                    if (ALTKeychainAccessWasDenied()) {
                        ALTKeychainEmitEvent(@"identity", ALTKeychainStatusDenied);
                        NSLog(@"[Error] Keychain access was denied while reading a team signing identity. Existing certificates were not revoked, and no new certificate request will be submitted.");
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    if (localKey && localCert) {
                        localCert.privateKey = localKey;
                        saveCertKey(localCert.identifier, localKey);
                        saveCertKey(localCert.serialNumber, localKey);
                        reusable = localCert;
                        emitCertificateEvent(@"reuse", @"system-identity");
                        NSLog(@"[Step 3] Reusing Apple Development identity from the system keychain");
                    }
                }
                if (reusable) {
                    continueWithCert(reusable);
                } else if (certs.count > 0 && !reissueCertificate) {
                    ALTKeychainEmitEvent(@"certificate-key", ALTKeychainStatusNotFound);
                    emitCertificateEvent(@"skip-create", @"missing-local-key");
                    NSLog(@"[Error] Apple already has a development certificate, but this Mac has no matching private key. Import a signing identity that includes the private key, or confirm reissuing on this Mac. Existing certificates were not revoked, and no new certificate request will be submitted.");
                    dispatch_semaphore_signal(sem);
                } else if (certs.count > 0 && reissueCertificate) {
                    emitCertificateEvent(@"reissue", @"user-confirmed");
                    NSLog(@"[Step 3] Reissuing development certificates after explicit user confirmation");
                    NSMutableArray<ALTCertificate *> *remaining = [certs mutableCopy];
                    __block void (^revokeNext)(void) = nil;
                    revokeNext = ^{
                        if (remaining.count == 0) {
                            emitCertificateEvent(@"create", @"reissue");
                            createNewCert();
                            revokeNext = nil;
                            return;
                        }
                        ALTCertificate *cert = remaining.firstObject;
                        [remaining removeObjectAtIndex:0];
                        NSLog(@"[Step 3] Revoking unmatched development certificate %@", cert.identifier);
                        [api revokeCertificate:cert team:team session:session completionHandler:^(BOOL ok, NSError *error) {
                            if (!ok || error) {
                                emitCertificateEvent(@"reissue-failed", @"revoke-rejected");
                                NSLog(@"[Error] Failed to revoke certificate %@: %@. No further certificates were revoked, and no new certificate request will be submitted.", cert.identifier, error);
                                dispatch_semaphore_signal(sem);
                                revokeNext = nil;
                                return;
                            }
                            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), revokeNext);
                        }];
                    };
                    revokeNext();
                } else {
                    emitCertificateEvent(@"create", @"no-portal-certs");
                    NSLog(@"[Step 3] No development certificates on the team; creating a new certificate");
                    createNewCert();
                }
            }];
        }];
    });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return succeeded;
}

static BOOL performList(NSString *appleID, NSString *password)
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL succeeded = NO;

    authenticateWithAppleID(appleID, password, ^(ALTAccount *account, ALTAppleAPISession *session, NSError *error) {
        if (error || !session) {
            NSLog(@"[Error] Authentication failed: %@", error);
            dispatch_semaphore_signal(sem);
            return;
        }
        NSLog(@"✅ Login successful! DSID: %@", account.identifier);

        ALTAppleAPI *api = [ALTAppleAPI sharedAPI];
        [api fetchTeamsForAccount:account session:session
                completionHandler:^(NSArray<ALTTeam *> *teams, NSError *error) {
            if (error || teams.count == 0) {
                NSLog(@"[Error] No teams found: %@", error);
                writeJSONResult(@{@"ok": @NO, @"code": @"no_teams"});
                dispatch_semaphore_signal(sem);
                return;
            }
            NSMutableArray *teamJSON = [NSMutableArray array];
            for (ALTTeam *team in teams) {
                NSLog(@"Team: %@ (%@)", team.name, team.identifier);
                [teamJSON addObject:@{
                    @"id": team.identifier ?: @"",
                    @"name": team.name ?: @""
                }];
            }
            writeJSONResult(@{
                @"ok": @YES,
                @"appleID": appleID ?: @"",
                @"teams": teamJSON
            });
            succeeded = YES;

            ALTTeam *team = teams.firstObject;
            [api fetchCertificatesForTeam:team session:session
                completionHandler:^(NSArray<ALTCertificate *> *certs, NSError *error) {
                if (error) {
                    NSLog(@"[Error] Failed to fetch certificates: %@", error);
                    dispatch_semaphore_signal(sem);
                    return;
                }
                if (certs.count > 0) {
                    NSLog(@"");
                    NSLog(@"📜 Certificates (%lu):", (unsigned long)certs.count);
                    for (ALTCertificate *cert in certs) {
                        NSLog(@"   %@ (%@)", cert.name, cert.identifier);
                    }
                } else {
                    NSLog(@"📜 No certificates found.");
                }

                [api fetchAppIDsForTeam:team session:session
                    completionHandler:^(NSArray<ALTAppID *> *appIDs, NSError *error) {
                    if (error) {
                        NSLog(@"[Error] Failed to fetch App IDs: %@", error);
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    if (appIDs.count > 0) {
                        NSLog(@"");
                        NSLog(@"📦 App IDs (%lu):", (unsigned long)appIDs.count);
                        for (ALTAppID *appID in appIDs) {
                            NSLog(@"   %@ (%@) name=%@", appID.bundleIdentifier, appID.identifier, appID.name);
                        }
                    } else {
                        NSLog(@"📦 No App IDs found.");
                    }
                    succeeded = YES;
                    dispatch_semaphore_signal(sem);
                }];
            }];
        }];
    });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return succeeded;
}

static BOOL performSession(void)
{
    NSString *cachedAppleID = nil;
    ALTAppleAPISession *cached = [ALTAppleAPISession loadSession:&cachedAppleID allowUI:NO];
    BOOL expired = cached != nil && cached.isExpired;
    BOOL valid = cached != nil && !expired && cachedAppleID.length > 0;
    NSMutableDictionary *result = [@{
        @"ok": @YES,
        @"valid": @(valid),
        @"expired": @(expired)
    } mutableCopy];
    if (cachedAppleID.length > 0) {
        result[@"appleID"] = cachedAppleID;
    }
    writeJSONResult(result);
    return valid;
}

// ============================================================
// main
// ============================================================

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        umask(0077);
        NSArray *args = [[NSProcessInfo processInfo] arguments];

        if (args.count < 2) {
            printUsage();
            return 1;
        }

        NSString *command = args[1];
        if ([command isEqualToString:@"--help"] ||
            [command isEqualToString:@"-h"] ||
            [command isEqualToString:@"help"]) {
            printUsage();
            return 0;
        }
        if (hasFlag(args, @"--password")) {
            fprintf(stderr,
                "Error: --password is not supported. `list --apple-id` reads the password from standard input.\n");
            return 64;
        }

        if (![command isEqualToString:@"sign"] &&
            ![command isEqualToString:@"list"] &&
            ![command isEqualToString:@"diagnose"] &&
            ![command isEqualToString:@"session"] &&
            ![command isEqualToString:@"logout"]) {
            fprintf(stderr, "Unknown command: %s\n\n", command.UTF8String);
            printUsage();
            return 64;
        }

        if ([command isEqualToString:@"sign"] &&
            hasFlag(args, @"--apple-id")) {
            fprintf(stderr,
                "Error: sign uses the cached session. Authenticate separately with `altsign-cli list --apple-id '<Apple ID>'`.\n");
            return 64;
        }

        if ([command isEqualToString:@"logout"]) {
            [ALTAppleAPISession deleteSession];
            ALTKeychainDeleteItems(kCertificateKeychainService, nil);
            return 0;
        }

        NSString *optionError = nil;
        if (!validateCommandOptions(args, command, &optionError)) {
            fprintf(stderr, "Error: %s.\n", optionError.UTF8String);
            return 64;
        }

        NSString *appleID = getArg(args, @"--apple-id");
        NSString *teamID = getArg(args, @"--team-id");
        NSString *udid = getArg(args, @"--udid");
        NSString *ipaPath = getArg(args, @"--ipa");
        NSString *appPath = getArg(args, @"--app");
        NSString *outputPath = getArg(args, @"--output");
        NSString *entitlementArg = getArg(args, @"--entitlement");
        ALTVerboseLogging = hasFlag(args, @"--verbose");

        if ([command isEqualToString:@"session"]) {
            return performSession() ? 0 : 2;
        }
        if ([command isEqualToString:@"diagnose"]) {
            return [ALTSRPAuthenticator runNetworkDiagnose];
        }

        if (hasFlag(args, @"--apple-id") && appleID.length == 0) {
            fprintf(stderr, "Error: --apple-id requires a value.\n");
            return 64;
        }
        NSString *password = nil;
        if ([command isEqualToString:@"list"] && appleID.length > 0) {
            NSString *cachedAppleID = nil;
            ALTAppleAPISession *cached =
                [ALTAppleAPISession loadSession:&cachedAppleID];
            if (![cachedAppleID isEqualToString:appleID] ||
                cached == nil || cached.isExpired) {
                NSError *passwordError = nil;
                password = readPasswordFromStandardInput(
                    appleID,
                    &passwordError
                );
                if (password.length == 0) {
                    fprintf(stderr, "Error: %s\n",
                        (passwordError.localizedDescription ?:
                            @"password was not provided").UTF8String);
                    return 2;
                }
            }
        } else {
            NSString *cachedAppleID = nil;
            ALTAppleAPISession *cached =
                [ALTAppleAPISession loadSession:&cachedAppleID];
            if (cached == nil || cached.isExpired || cachedAppleID.length == 0) {
                fprintf(stderr,
                    "Error: no valid cached session. Run `altsign-cli list --apple-id '<Apple ID>'` first.\n");
                return 2;
            }
            appleID = cachedAppleID;
        }

        NSArray<NSString *> *entitlementNames = @[];
        if (entitlementArg.length > 0) {
            NSMutableArray *names = [NSMutableArray array];
            for (NSString *part in [entitlementArg componentsSeparatedByString:@","]) {
                NSString *trimmed = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                if (trimmed.length > 0) {
                    NSString *lower = trimmed.lowercaseString;
                    if (capabilityFeatureMap()[lower]) {
                        [names addObject:lower];
                    } else {
                        fprintf(stderr, "Warning: unknown entitlement '%s', skipping\n", trimmed.UTF8String);
                    }
                }
            }
            entitlementNames = names;
        }

        if ([command isEqualToString:@"sign"]) {
            if (ipaPath && appPath) {
                fprintf(stderr, "Error: use either --ipa or --app, not both\n\n");
                printUsage();
                return 1;
            }
            NSString *inputPath = ipaPath ?: appPath;
            if (!udid || !inputPath) {
                fprintf(stderr, "Error: --udid and one of --ipa/--app are required for sign command\n\n");
                printUsage();
                return 1;
            }
            if (teamID.length == 0) {
                fprintf(stderr, "Error: --team-id is required for sign command\n\n");
                printUsage();
                return 1;
            }
            if (!outputPath) {
                NSString *base = [inputPath stringByDeletingPathExtension];
                outputPath = [base stringByAppendingString:@"_signed.ipa"];
            }
            return performSign(
                appleID,
                nil,
                teamID,
                udid,
                inputPath,
                outputPath,
                entitlementNames,
                hasFlag(args, @"--reissue-certificate")
            ) ? 0 : 1;

        } else if ([command isEqualToString:@"list"]) {
            return performList(appleID, password) ? 0 : 1;
        }

        return 64;
    }
}
