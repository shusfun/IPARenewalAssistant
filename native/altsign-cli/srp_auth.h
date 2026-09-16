//
//  srp_auth.h
//  AltSign CLI
//
//  Apple SRP (Secure Remote Password) 认证协议实现
//

#import <Foundation/Foundation.h>
#import "anisette.h"

NS_ASSUME_NONNULL_BEGIN

/// Apple API 会话（认证后获得）
@interface ALTAppleAPISession : NSObject
@property (nonatomic, copy) NSString *dsid;          // Directory Services ID
@property (nonatomic, copy) NSString *authToken;     // Xcode Auth Token
@property (nonatomic, strong) ALTAnisetteData *anisetteData;
@property (nonatomic, strong, nullable) NSDate *expirationDate; // Token 过期时间

- (instancetype)initWithDSID:(NSString *)dsid
                   authToken:(NSString *)authToken
                anisetteData:(ALTAnisetteData *)anisetteData;

/// 保存 session 到登录钥匙串（已有条目走更新，不删除重建）
- (BOOL)saveForAppleID:(NSString *)appleID;

/// 加载单一缓存 session，通过 outAppleID 返回对应的 Apple ID
+ (nullable instancetype)loadSession:(NSString *_Nullable *_Nullable)outAppleID;

/// 加载缓存 session。allowUI=NO 时访问失败不会弹出钥匙串授权。
+ (nullable instancetype)loadSession:(NSString *_Nullable *_Nullable)outAppleID allowUI:(BOOL)allowUI;

/// 删除本地保存的 session
+ (void)deleteSession;

/// 判断 session 是否已过期（预留 5 分钟缓冲）
- (BOOL)isExpired;
@end

/// Apple 帐号信息
@interface ALTAccount : NSObject
@property (nonatomic, copy) NSString *appleID;
@property (nonatomic, copy) NSString *identifier;  // dsid
@property (nonatomic, copy) NSString *firstName;
@property (nonatomic, copy) NSString *lastName;
@end

/// 全局 verbose 日志开关
extern BOOL ALTVerboseLogging;

/// 2FA 验证码处理器
typedef void (^ALTVerificationHandler)(
    void (^ _Nonnull)(NSString * _Nullable verificationCode),
    void (^ _Nonnull resend)(void (^ _Nonnull)(NSError * _Nullable error))
);

/// SRP 认证器
@interface ALTSRPAuthenticator : NSObject

/// 使用 Apple ID + 密码 + Anisette 数据进行 SRP 登录
/// 完成后返回 ALTAccount + ALTAppleAPISession
+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              completionHandler:(void (^)(ALTAccount * _Nullable account,
                                         ALTAppleAPISession * _Nullable session,
                                         NSError * _Nullable error))completion;

/// 带 2FA 验证码回调的 SRP 登录
/// verificationHandler 被调用时，需要向用户索取 6 位验证码，然后调用回调传入
+ (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              verificationHandler:(nullable ALTVerificationHandler)verificationHandler
              completionHandler:(void (^)(ALTAccount * _Nullable account,
                                         ALTAppleAPISession * _Nullable session,
                                         NSError * _Nullable error))completion;

/// 无凭据网络诊断：最小 GET / 客户端标识 / Anisette / 进程级出口对照。
/// 不登录、不读取密码。返回 0 表示诊断跑完（不表示认证成功）。
+ (int)runNetworkDiagnose;

/// 提交 2FA 验证码（独立步骤）
+ (void)submitTwoFactorCode:(NSString *)code
                       dsid:(NSString *)dsid
                  idmsToken:(NSString *)idmsToken
               anisetteData:(ALTAnisetteData *)anisetteData
          completionHandler:(void (^)(BOOL success, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
