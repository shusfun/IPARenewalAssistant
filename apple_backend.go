package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type pendingLogin struct {
	appleID    string
	accountRef string
	createdAt  time.Time
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	done       chan loginResult
	challenge  chan struct{}
	resend     chan error
	closed     bool
}

type loginResult struct {
	stdout []byte
	stderr []byte
	err    error
}

type AppleBackend struct {
	mu      sync.Mutex
	pending map[string]pendingLogin
}

type signerJSON struct {
	OK      bool         `json:"ok"`
	Valid   bool         `json:"valid"`
	Expired bool         `json:"expired"`
	AppleID string       `json:"appleID"`
	Code    string       `json:"code"`
	Teams   []signerTeam `json:"teams"`
}

type signerTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func newAppleBackend() *AppleBackend { return &AppleBackend{pending: make(map[string]pendingLogin)} }

func parseSignerJSON(stdout []byte) (signerJSON, error) {
	text := strings.TrimSpace(string(stdout))
	if text == "" {
		return signerJSON{}, fmt.Errorf("签名组件没有返回机器可读结果")
	}
	lines := strings.Split(text, "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		line := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var parsed signerJSON
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			return parsed, nil
		}
	}
	var parsed signerJSON
	if err := json.Unmarshal([]byte(text), &parsed); err == nil {
		return parsed, nil
	}
	return signerJSON{}, fmt.Errorf("无法解析签名组件结果")
}

func (s *Service) appleBackendReady() bool { return signerPath() != "" }

type gsaDiagEvent struct {
	Stage      string
	Method     string
	Status     string
	DurationMS string
	Content    string
	Proxy      string
}

func parseGSAEvents(stderr []byte) []gsaDiagEvent {
	var events []gsaDiagEvent
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "EVENT:gsa ") {
			continue
		}
		event := gsaDiagEvent{}
		for _, field := range strings.Fields(strings.TrimPrefix(line, "EVENT:gsa ")) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch key {
			case "stage":
				event.Stage = value
			case "method":
				event.Method = value
			case "status":
				event.Status = value
			case "duration_ms":
				event.DurationMS = value
			case "content":
				event.Content = value
			case "proxy":
				event.Proxy = value
			}
		}
		if event.Stage != "" {
			events = append(events, event)
		}
	}
	return events
}

func appleLoginError(result loginResult) error {
	events := parseGSAEvents(result.stderr)
	if len(events) > 0 {
		var parts []string
		authStage := ""
		twoFactorDenied := false
		for _, event := range events {
			label := event.Stage
			if event.Method != "" {
				label += " " + event.Method
			}
			detail := "HTTP " + event.Status
			if event.Content != "" {
				detail += "（" + event.Content + "）"
			}
			if event.DurationMS != "" {
				detail += "，" + event.DurationMS + "ms"
			}
			parts = append(parts, label+" "+detail)
			if event.Stage == "init" || event.Stage == "complete" {
				authStage = event.Stage
			}
			if event.Stage == "2fa-request" && (event.Status == "403" || event.Status == "401" || event.Status == "failed") {
				twoFactorDenied = true
			}
		}
		if twoFactorDenied {
			return &UserError{
				Code:     "apple_2fa_not_sent",
				Message:  "密码已通过，但 Apple 拒绝发送二次验证码。这台电脑当前被当作已验证设备，验证码不会出现。",
				Recovery: "不要改密码，也不要连续重试。下一步需要改用系统登录，或在尚未信任的设备上完成验证。",
			}
		}
		message := "认证请求未完成：" + strings.Join(parts, "；")
		if events[0].Proxy != "" {
			message += "。进程代理=" + events[0].Proxy
		}
		recovery := "这不能证明 Apple 全局故障。请稍后再试一次，不要改密码，也不要连续重试。"
		code := "apple_auth_rejected"
		if authStage == "init" {
			code = "apple_auth_init_rejected"
		} else if authStage == "complete" {
			code = "apple_auth_complete_rejected"
		}
		return &UserError{Code: code, Message: message, Recovery: recovery}
	}
	combined := strings.ToLower(string(result.stderr) + "\n" + string(result.stdout))
	if result.err != nil {
		combined += "\n" + strings.ToLower(result.err.Error())
	}
	if strings.Contains(combined, "http 503") || strings.Contains(combined, "http 502") || strings.Contains(combined, "http 500") || strings.Contains(combined, "service temporarily unavailable") {
		return &UserError{Code: "apple_auth_rejected", Message: "认证接口返回 HTTP 5xx，尚未区分服务端、出口路径或协议不被接受", Recovery: "请稍后再试一次，不要改密码，也不要连续重试。"}
	}
	return commandError("apple_login_failed", "Apple ID 登录失败", "请检查 Apple ID 和密码后重试。", CommandResult{Stdout: result.stdout, Stderr: result.stderr}, result.err)
}

func parseHelperEvents(stderr []byte, prefix string) []map[string]string {
	var events []map[string]string
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := map[string]string{}
		for _, field := range strings.Fields(strings.TrimPrefix(line, prefix)) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			fields[key] = value
		}
		if len(fields) > 0 {
			events = append(events, fields)
		}
	}
	return events
}

func appleSignError(result CommandResult, runErr error) error {
	for _, event := range parseHelperEvents(result.Stderr, "EVENT:sign ") {
		switch event["step"] {
		case "import":
			return &UserError{
				Code:     "signing_identity_import_failed",
				Message:  "开发证书已准备好，但无法导入本机临时钥匙串。",
				Recovery: "请重试签名。不要再重新签发证书。",
			}
		case "identity":
			if event["status"] == "mismatch" || event["reason"] == "p12" {
				return &UserError{
					Code:     "signing_identity_unusable",
					Message:  "本机保存的私钥与开发证书不匹配，无法生成签名身份。",
					Recovery: "请重试签名。不要再重新签发证书。若仍然失败，把新的错误码发我。",
				}
			}
			return &UserError{
				Code:     "signing_identity_unusable",
				Message:  "开发证书和私钥已找到，但未能得到可用的代码签名身份。",
				Recovery: "请重试签名。不要再重新签发证书。",
			}
		case "codesign":
			switch event["reason"] {
			case "keychain":
				return &UserError{
					Code:     "codesign_failed",
					Message:  "代码签名无法使用临时钥匙串里的身份。",
					Recovery: "请重试签名。不要再重新签发证书。",
				}
			case "no-identity":
				return &UserError{
					Code:     "codesign_failed",
					Message:  "codesign 找不到刚导入的签名身份。",
					Recovery: "请重试签名。不要再重新签发证书。",
				}
			case "entitlements":
				return &UserError{
					Code:     "codesign_failed",
					Message:  "无法把权限写入代码签名。",
					Recovery: "请重试签名。不要再重新签发证书。",
				}
			case "busy":
				return &UserError{
					Code:     "codesign_failed",
					Message:  "应用文件正被占用，无法写入签名。",
					Recovery: "请关闭可能打开该 App 的程序后重试。不要重新签发证书。",
				}
			default:
				return &UserError{
					Code:     "codesign_failed",
					Message:  "代码签名失败。",
					Recovery: "请重试签名。不要再重新签发证书。",
				}
			}
		}
	}
	for _, event := range parseHelperEvents(result.Stderr, "EVENT:keychain ") {
		switch event["status"] {
		case "denied", "unavailable":
			return &UserError{
				Code:     "signing_key_access_denied",
				Message:  "本机钥匙串拒绝访问签名所需的私钥或登录会话。这不能证明私钥不存在。",
				Recovery: "若弹框来自 altsign-cli，并写明要访问登录钥匙串中的项目，可输入该钥匙串密码并点“始终允许”。取消后本次任务会结束，不会继续申请证书。",
			}
		}
	}
	for _, event := range parseHelperEvents(result.Stderr, "EVENT:certificate ") {
		if event["action"] == "skip-create" || event["reason"] == "missing-local-key" {
			return &UserError{
				Code:     "signing_identity_missing",
				Message:  "Apple 开发者账户里已有开发证书，但这台 Mac 没有匹配的私钥。",
				Recovery: "Apple 不会下发旧私钥。可导入含私钥的 .p12，或在提示中确认后用当前登录账号在这台 Mac 重新签发（会作废现有开发证书）。",
			}
		}
		if event["action"] == "reissue-failed" {
			return commandError("certificate_reissue_failed", "无法作废账户里现有的开发证书", "没有继续申请新证书。请稍后再试，或改为导入含私钥的 .p12。", result, runErr)
		}
		if event["action"] == "create-failed" {
			return commandError("sign_failed", "无法创建新的开发证书", "已有证书不会被自动撤销。若本机仍无私钥，请在提示中确认重新签发，或导入含私钥的签名身份。", result, runErr)
		}
	}
	filtered := result
	filtered.Stderr = []byte(filterHelperNoise(string(result.Stderr)))
	filtered.Stdout = []byte(filterHelperNoise(string(result.Stdout)))
	return commandError("sign_failed", "Apple ID 签名失败", "请确认账号仍有效。若提示已有开发证书，需要本机钥匙串里带私钥的同一张证书；已有证书不会被撤销。", filtered, runErr)
}

func filterHelperNoise(text string) string {
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "0x") && strings.Contains(trim, "<uint32>") {
			continue
		}
		if strings.HasPrefix(trim, "0x") && strings.Contains(trim, "<blob>") {
			continue
		}
		if trim == "attributes:" {
			continue
		}
		keep = append(keep, trim)
	}
	if len(keep) > 8 {
		keep = keep[len(keep)-8:]
	}
	return strings.Join(keep, "\n")
}

func signerPath() string {
	if value := strings.TrimSpace(os.Getenv("IPARENEWAL_SIGNER")); value != "" {
		if info, err := os.Stat(value); err == nil && !info.IsDir() {
			return value
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	for _, candidate := range []string{
		filepath.Join(filepath.Dir(exe), "..", "Resources", "altsign-cli"),
		filepath.Join(filepath.Dir(exe), "altsign-cli"),
	} {
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func accountRefForEmail(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "apple-" + hex.EncodeToString(sum[:])[:16]
}

func (s *Service) storedAppleAccountReady() bool {
	state := s.store.Snapshot()
	return state.AppleAccount != nil && state.AppleAccount.AccountRef != "" && s.keychainHasAccount(state.AppleAccount.AccountRef)
}

func (s *Service) GetAppleAccountStatus() AppleAccountStatus {
	state := s.store.Snapshot()
	if !s.storedAppleAccountReady() {
		return AppleAccountStatus{}
	}
	session := s.nativeSession()
	if !session.Valid || session.Expired {
		return AppleAccountStatus{}
	}
	if session.AppleID != "" && accountRefForEmail(session.AppleID) != state.AppleAccount.AccountRef {
		return AppleAccountStatus{}
	}
	return AppleAccountStatus{SignedIn: true, AccountRef: state.AppleAccount.AccountRef,
		TeamID: state.AppleAccount.TeamID, TeamName: state.AppleAccount.TeamName,
		NeedsTeam: state.AppleAccount.TeamID == "", Teams: state.AppleAccount.Teams}
}

func (s *Service) nativeSession() signerJSON {
	path := signerPath()
	if path == "" {
		return signerJSON{}
	}
	result, err := s.runner.Run(context.Background(), CommandSpec{Name: path, Args: []string{"session"}, Timeout: 8 * time.Second})
	parsed, parseErr := parseSignerJSON(result.Stdout)
	if parseErr != nil {
		return signerJSON{}
	}
	if err != nil && !parsed.Valid {
		return parsed
	}
	return parsed
}

func (s *Service) StartAppleLogin(appleID, password string) (LoginChallenge, error) {
	if _, err := mail.ParseAddress(appleID); err != nil || !strings.Contains(appleID, "@") {
		return LoginChallenge{}, &UserError{Code: "apple_id_invalid", Message: "请输入有效的 Apple ID 邮箱"}
	}
	if strings.TrimSpace(password) == "" {
		return LoginChallenge{}, &UserError{Code: "apple_password_missing", Message: "请输入 Apple ID 密码"}
	}
	_ = s.RememberAppleCredentials(strings.TrimSpace(appleID), password)
	if !s.appleBackendReady() {
		return LoginChallenge{}, &UserError{Code: "signing_backend_missing", Message: "内置签名组件未安装", Recovery: "请重新构建应用并确保 altsign-cli 位于应用 Resources 目录。"}
	}
	authID := fmt.Sprintf("auth-%d", time.Now().UnixNano())
	cmd := exec.Command(signerPath(), "list", "--apple-id", strings.TrimSpace(appleID))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return LoginChallenge{}, &UserError{Code: "apple_login_start_failed", Message: "无法启动 Apple 登录组件"}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return LoginChallenge{}, &UserError{Code: "apple_login_start_failed", Message: "无法读取 Apple 登录组件输出"}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return LoginChallenge{}, &UserError{Code: "apple_login_start_failed", Message: "无法读取 Apple 登录组件状态"}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	login := pendingLogin{appleID: strings.TrimSpace(appleID), accountRef: accountRefForEmail(appleID), createdAt: s.now(), cmd: cmd, stdin: stdin, done: make(chan loginResult, 1), challenge: make(chan struct{}, 1), resend: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return LoginChallenge{}, &UserError{Code: "apple_login_start_failed", Message: "无法启动 Apple 登录组件", Recovery: redact(err.Error())}
	}
	// Password is sent once and then discarded. The pipe stays open for the 2FA code.
	secret := []byte(password + "\n")
	_, writeErr := stdin.Write(secret)
	for i := range secret {
		secret[i] = 0
	}
	if writeErr != nil {
		_ = cmd.Process.Kill()
		return LoginChallenge{}, &UserError{Code: "apple_login_start_failed", Message: "无法发送登录请求"}
	}
	s.apple.mu.Lock()
	s.apple.pending[authID] = login
	s.apple.mu.Unlock()
	go s.watchAppleLogin(authID, &login, stdout, stderr)
	select {
	case <-login.challenge:
		return LoginChallenge{AuthID: authID, NeedsTwoFactor: true, Message: "已发送到受信任设备，请输入 6 位验证码"}, nil
	case result := <-login.done:
		s.removePending(authID)
		if result.err != nil {
			err := appleLoginError(result)
			if userErr, ok := err.(*UserError); ok {
				s.audit(AuditEvent{Kind: "login", Stage: "auth", Status: "failed", ErrorCode: userErr.Code, Message: userErr.Message})
			}
			return LoginChallenge{}, err
		}
		if _, err := s.finishAppleLogin(login, result.stdout); err != nil {
			return LoginChallenge{}, err
		}
		return LoginChallenge{AuthID: authID, NeedsTwoFactor: false, Message: "Apple ID 已登录"}, nil
	case <-time.After(45 * time.Second):
		s.stopPending(authID)
		return LoginChallenge{}, &UserError{Code: "apple_login_timeout", Message: "Apple 登录请求超时", Recovery: "请检查网络后重试。"}
	}
}

func (s *Service) SubmitTwoFactor(authID, code string) (AppleAccountStatus, error) {
	s.apple.mu.Lock()
	pending, ok := s.apple.pending[authID]
	s.apple.mu.Unlock()
	if !ok || time.Since(pending.createdAt) > 10*time.Minute {
		return AppleAccountStatus{}, &UserError{Code: "apple_auth_expired", Message: "登录请求已过期，请重新输入 Apple ID 和密码"}
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return AppleAccountStatus{}, &UserError{Code: "apple_2fa_invalid", Message: "验证码应为 6 位数字"}
	}
	if _, err := pending.stdin.Write([]byte(code + "\n")); err != nil {
		s.removePending(authID)
		return AppleAccountStatus{}, &UserError{Code: "apple_2fa_submit_failed", Message: "验证码发送失败，请重新登录"}
	}
	select {
	case result := <-pending.done:
		s.removePending(authID)
		if result.err != nil {
			return AppleAccountStatus{}, commandError("apple_2fa_invalid", "验证码验证失败", "请确认设备上显示的验证码后重试。", CommandResult{Stdout: result.stdout, Stderr: result.stderr}, result.err)
		}
		return s.finishAppleLogin(pending, result.stdout)
	case <-time.After(3 * time.Minute):
		s.stopPending(authID)
		return AppleAccountStatus{}, &UserError{Code: "apple_2fa_timeout", Message: "验证码验证超时，请重新登录"}
	}
}

func (s *Service) watchAppleLogin(authID string, login *pendingLogin, stdout io.Reader, stderr io.Reader) {
	var out, errOut strings.Builder
	lines := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			errOut.WriteString(line)
			errOut.WriteByte('\n')
			lower := strings.ToLower(line)
			if strings.Contains(lower, "event:challenge") || strings.Contains(lower, "2fa verification required") {
				lines <- "challenge"
			}
			if strings.Contains(lower, "event:resend-result:ok") {
				login.resend <- nil
			}
			if strings.Contains(lower, "event:resend-result:error:") {
				login.resend <- fmt.Errorf("%s", strings.TrimSpace(line[strings.Index(lower, "event:resend-result:error:")+len("event:resend-result:error:"):]))
			}
		}
		close(lines)
	}()
	go func() { _, _ = io.Copy(&out, stdout) }()
	challengeSent := false
	for line := range lines {
		if line == "challenge" && !challengeSent {
			challengeSent = true
			login.challenge <- struct{}{}
		}
	}
	err := login.cmd.Wait()
	login.done <- loginResult{stdout: []byte(out.String()), stderr: []byte(errOut.String()), err: err}
}

func (s *Service) removePending(authID string) {
	s.apple.mu.Lock()
	login, ok := s.apple.pending[authID]
	delete(s.apple.pending, authID)
	s.apple.mu.Unlock()
	if ok {
		_ = login.stdin.Close()
	}
}

func (s *Service) stopPending(authID string) {
	s.apple.mu.Lock()
	login, ok := s.apple.pending[authID]
	delete(s.apple.pending, authID)
	s.apple.mu.Unlock()
	if !ok {
		return
	}
	if login.stdin != nil {
		_ = login.stdin.Close()
	}
	killLoginProcess(login.cmd)
}

func killLoginProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}

func (s *Service) finishAppleLogin(pending pendingLogin, stdout []byte) (AppleAccountStatus, error) {
	parsed, err := parseSignerJSON(stdout)
	if err != nil || !parsed.OK {
		return AppleAccountStatus{}, &UserError{Code: "apple_login_failed", Message: "Apple ID 已验证，但无法读取开发团队列表", Recovery: "请重新登录。"}
	}
	if parsed.AppleID != "" && accountRefForEmail(parsed.AppleID) != pending.accountRef {
		return AppleAccountStatus{}, &UserError{Code: "apple_login_failed", Message: "登录会话与当前 Apple ID 不一致"}
	}
	teams := make([]DeveloperTeam, 0, len(parsed.Teams))
	seen := map[string]bool{}
	for _, team := range parsed.Teams {
		id := strings.TrimSpace(team.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		teams = append(teams, DeveloperTeam{ID: id, Name: strings.TrimSpace(team.Name)})
	}
	if len(teams) == 0 {
		return AppleAccountStatus{}, &UserError{Code: "apple_login_failed", Message: "当前 Apple ID 没有可用的开发团队"}
	}
	if err := s.saveKeychainAccount(pending.accountRef); err != nil {
		return AppleAccountStatus{}, &UserError{Code: "keychain_write_failed", Message: "无法将登录会话保存到 macOS 钥匙串", Recovery: "请允许钥匙串访问后重试。"}
	}
	if err := s.store.Update(func(state *State) error {
		teamID, teamName := "", ""
		if len(teams) == 1 {
			teamID, teamName = teams[0].ID, teams[0].Name
		}
		state.AppleAccount = &AppleAccountState{AccountRef: pending.accountRef, TeamID: teamID, TeamName: teamName, Teams: teams, AuthenticatedAt: s.now()}
		return nil
	}); err != nil {
		return AppleAccountStatus{}, err
	}
	return s.GetAppleAccountStatus(), nil
}

func (s *Service) ResendTwoFactor(authID string) error {
	s.apple.mu.Lock()
	login, ok := s.apple.pending[authID]
	s.apple.mu.Unlock()
	if !ok {
		return &UserError{Code: "apple_auth_expired", Message: "登录请求已结束，请重新登录"}
	}
	if _, err := login.stdin.Write([]byte("resend\n")); err != nil {
		return &UserError{Code: "apple_2fa_resend_failed", Message: "无法重新发送验证码"}
	}
	select {
	case err := <-login.resend:
		if err != nil {
			return &UserError{Code: "apple_2fa_resend_failed", Message: "Apple 未接受重新发送请求", Recovery: redact(err.Error())}
		}
		return nil
	case <-time.After(35 * time.Second):
		return &UserError{Code: "apple_2fa_resend_timeout", Message: "重新发送请求超时"}
	}
}

func (s *Service) CancelAppleLogin(authID string) error {
	s.stopPending(authID)
	return nil
}

func (s *Service) SelectDeveloperTeam(teamID string) error {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return &UserError{Code: "team_id_missing", Message: "开发团队不能为空"}
	}
	return s.store.Update(func(state *State) error {
		if state.AppleAccount == nil {
			return &UserError{Code: "apple_account_missing", Message: "请先登录 Apple ID"}
		}
		var name string
		found := false
		for _, team := range state.AppleAccount.Teams {
			if team.ID == teamID {
				name = team.Name
				found = true
				break
			}
		}
		if !found {
			return &UserError{Code: "team_id_unknown", Message: "所选开发团队不在当前账号的团队列表中"}
		}
		state.AppleAccount.TeamID = teamID
		state.AppleAccount.TeamName = name
		return nil
	})
}

func (s *Service) SignOutAppleAccount() error {
	state := s.store.Snapshot()
	if state.AppleAccount != nil {
		_ = s.deleteKeychainAccount(state.AppleAccount.AccountRef)
	}
	if path := signerPath(); path != "" {
		_, _ = s.runner.Run(context.Background(), CommandSpec{Name: path, Args: []string{"logout"}, Timeout: 15 * time.Second})
	}
	return s.store.Update(func(state *State) error { state.AppleAccount = nil; return nil })
}

func (s *Service) saveKeychainAccount(accountRef string) error {
	args := []string{"add-generic-password", "-U", "-T", "/usr/bin/security"}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		args = append(args, "-T", exe)
	}
	args = append(args, "-a", accountRef, "-s", appBundleID+".apple-session", "-w", "authenticated")
	return exec.Command("/usr/bin/security", args...).Run()
}

func (s *Service) keychainHasAccount(accountRef string) bool {
	_, err := s.runner.Run(context.Background(), CommandSpec{
		Name: "/usr/bin/security", Args: []string{"find-generic-password", "-a", accountRef, "-s", appBundleID + ".apple-session"}, Timeout: 8 * time.Second,
	})
	return err == nil
}

func (s *Service) deleteKeychainAccount(accountRef string) error {
	return exec.Command("/usr/bin/security", "delete-generic-password", "-a", accountRef,
		"-s", appBundleID+".apple-session").Run()
}

const appleCredentialsService = appBundleID + ".apple-credentials"

func (s *Service) RememberAppleCredentials(appleID, password string) error {
	appleID = strings.TrimSpace(appleID)
	if appleID == "" || password == "" {
		return &UserError{Code: "apple_credentials_incomplete", Message: "记住账号需要邮箱和密码"}
	}
	_ = s.store.Update(func(state *State) error {
		state.LastAppleID = appleID
		return nil
	})
	_, err := s.runner.Run(context.Background(), CommandSpec{
		Name:    "/usr/bin/security",
		Args:    []string{"add-generic-password", "-U", "-s", appleCredentialsService, "-a", appleID, "-w", password},
		Timeout: 8 * time.Second,
	})
	if err != nil {
		return &UserError{Code: "apple_credentials_save_failed", Message: "无法把密码写入本机钥匙串", Recovery: "请允许钥匙串访问后重新点登录，应用不会把密码写进状态文件。"}
	}
	return nil
}

func (s *Service) RememberedAppleCredentials() RememberedAppleCredentials {
	appleID := strings.TrimSpace(s.store.Snapshot().LastAppleID)
	if appleID == "" {
		if migrated := s.readLegacyRememberedJSON(); migrated.AppleID != "" {
			_ = s.RememberAppleCredentials(migrated.AppleID, migrated.Password)
			return migrated
		}
		return RememberedAppleCredentials{}
	}
	result, err := s.runner.Run(context.Background(), CommandSpec{
		Name:    "/usr/bin/security",
		Args:    []string{"find-generic-password", "-s", appleCredentialsService, "-a", appleID, "-w"},
		Timeout: 8 * time.Second,
	})
	if err != nil {
		return RememberedAppleCredentials{AppleID: appleID}
	}
	password := strings.TrimSpace(string(result.Stdout))
	if password == "" {
		return RememberedAppleCredentials{AppleID: appleID}
	}
	return RememberedAppleCredentials{AppleID: appleID, Password: password}
}

func (s *Service) readLegacyRememberedJSON() RememberedAppleCredentials {
	result, err := s.runner.Run(context.Background(), CommandSpec{
		Name:    "/usr/bin/security",
		Args:    []string{"find-generic-password", "-s", appleCredentialsService, "-a", "remembered", "-w"},
		Timeout: 8 * time.Second,
	})
	if err != nil {
		return RememberedAppleCredentials{}
	}
	var creds RememberedAppleCredentials
	if json.Unmarshal(bytes.TrimSpace(result.Stdout), &creds) != nil {
		return RememberedAppleCredentials{}
	}
	return creds
}
