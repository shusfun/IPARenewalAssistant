import {useCallback, useEffect, useMemo, useRef, useState} from 'react'
import {
  AlertCircle, AppWindow, CheckCircle2, ChevronDown, Download, FolderOpen,
  HardDrive, Import, LoaderCircle, MoreHorizontal, RefreshCw, RotateCw, ShieldCheck,
  Smartphone, Unplug, X, XCircle,
} from 'lucide-react'
import {
  CancelJob, CheckEnvironment, InstallApp, ListDevices, ListManagedApps,
  ListSigningIdentities, RenewApp, RevealSignedIPA, SelectAndImportIPA,
  SelectSigningIdentity, SignApp, GetAppleAccountStatus, StartAppleLogin, RememberAppleCredentials, RememberedAppleCredentials,
  SubmitTwoFactor, SignOutAppleAccount, ListAuditEvents, ResendTwoFactor, CancelAppleLogin,
  SelectDeveloperTeam,
} from '../wailsjs/go/main/App'
import {EventsOff, EventsOn, SendNotification, WindowIsMinimised} from '../wailsjs/runtime/runtime'
import './App.css'

type EnvironmentStatus = {
  platformSupported: boolean
  platformIssue?: string
  volumeAvailable: boolean
  volumeIssue?: string
  signingBackendReady: boolean
  deviceBackendReady: boolean
  accountReady: boolean
  canImport: boolean
  canSign: boolean
  canInstall: boolean
  identityReady: boolean
  identityCount: number
  toolsReady: boolean
  ready: boolean
  issues: string[]
}

type Device = {
  id: string
  name: string
  osVersion: string
  connection: string
  developerMode: string
  pairing?: string
  available: boolean
  channels?: string[]
  installServiceReady?: boolean
}

export type ManagedApp = {
  id: string
  name: string
  version: string
  buildVersion: string
  originalBundleID: string
  effectiveBundleID: string
  minimumOS?: string
  iconDataURL?: string
  importedAt: string
  signed: boolean
  signedAt?: string
  installed: boolean
  installedAt?: string
  expirationTime?: string
  validityStatus: 'valid' | 'expiring' | 'expired' | 'unsigned'
  remainingSeconds: number
  canRenew: boolean
}

type JobProgress = { jobID: string; kind: string; step: string; message: string; percent: number }
type JobFinished = { jobID: string; kind: string; success: boolean; message: string; code?: string }
type SigningIdentity = {id: string; label: string; selected: boolean}
type AuditEvent = {id: string; jobID?: string; at: string; kind: string; stage: string; status: string; appID?: string; bundleID?: string; deviceID?: string; errorCode?: string; message?: string}
type Notice = {id: string; level: 'success' | 'error' | 'warning'; title: string; message: string; code?: string}
type AccountStatus = {signedIn: boolean; accountRef?: string; teamID?: string; teamName?: string; needsTeam?: boolean; teams?: {id: string; name: string}[]}
type OpenMenu = 'account' | 'more' | 'device' | 'identity' | null

const emptyEnvironment: EnvironmentStatus = {
  platformSupported: false, volumeAvailable: false, signingBackendReady: false, deviceBackendReady: false, accountReady: false, canImport: false, canSign: false, canInstall: false, identityReady: false,
  identityCount: 0, toolsReady: false, ready: false, issues: [],
}

const previewParams = new URLSearchParams(window.location.search)
const previewMode = import.meta.env.DEV && previewParams.has('preview')
const previewNetwork = previewMode && previewParams.has('network')
const previewSignedIn = previewMode && (previewParams.has('signedIn') || previewParams.has('longTeam') || previewParams.has('needsTeam'))
const previewLongTeam = previewMode && previewParams.has('longTeam')
const previewNeedsTeam = previewMode && previewParams.has('needsTeam')
const previewMultiDevice = previewMode && previewParams.has('multiDevice')
const previewIdentitiesEnabled = previewMode && previewParams.has('identities')
const previewUnconfirmed = previewMode && previewParams.has('unconfirmed')
const previewTeamName = previewLongTeam ? 'North Atlantic Independent Software Cooperative Limited' : '示例团队'
const previewEnvironment: EnvironmentStatus = {platformSupported: true, volumeAvailable: true, signingBackendReady: true, deviceBackendReady: true, accountReady: true, canImport: true, canSign: true, canInstall: true, identityReady: true, identityCount: 1, toolsReady: true, ready: true, issues: []}
const previewDevices: Device[] = [
  {id: 'preview-device', name: 'iPhone', osVersion: '27.0', connection: previewNetwork ? 'network' : 'USB', developerMode: '已开启', pairing: '已配对', available: true, installServiceReady: true},
  ...(previewMultiDevice ? [{id: 'preview-device-2', name: 'iPad Pro', osVersion: '18.6', connection: 'USB', developerMode: '已开启', pairing: '已配对', available: true}] : []),
]
const previewApps: ManagedApp[] = [{id: 'preview-app', name: '示例应用', version: '2.4.1', buildVersion: '241', originalBundleID: 'org.example.sample', effectiveBundleID: 'org.example.sample', minimumOS: '15.0', importedAt: new Date().toISOString(), signed: true, signedAt: new Date().toISOString(), installed: !previewUnconfirmed, installedAt: previewUnconfirmed ? undefined : new Date().toISOString(), expirationTime: previewUnconfirmed ? undefined : new Date(Date.now() + 61 * 3600_000).toISOString(), validityStatus: previewUnconfirmed ? 'unsigned' : 'expiring', remainingSeconds: previewUnconfirmed ? 0 : 61 * 3600, canRenew: !previewUnconfirmed}]
const previewAccount: AccountStatus = previewSignedIn
  ? {signedIn: true, accountRef: 'preview-account', teamID: previewNeedsTeam ? '' : 'TEAM1', teamName: previewNeedsTeam ? '' : previewTeamName, needsTeam: previewNeedsTeam, teams: [{id: 'TEAM1', name: previewTeamName}, {id: 'TEAM2', name: '另一个团队'}]}
  : {signedIn: false}
const previewIdentities: SigningIdentity[] = previewIdentitiesEnabled
  ? [{id: 'id1', label: 'Apple Development: Preview One', selected: true}, {id: 'id2', label: 'Apple Development: Preview Two', selected: false}]
  : []
function errorText(error: unknown): string {
  if (typeof error === 'string') return error
  if (error instanceof Error) return error.message
  if (error && typeof error === 'object' && 'message' in error) return String(error.message)
  return '操作失败，请重试。'
}

export function formatRemaining(seconds: number): string {
  if (seconds <= 0) return '已过期'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  return days > 0 ? `${days} 天 ${hours} 小时` : `${Math.max(hours, 1)} 小时`
}

export function developerModeLabel(mode?: string): string {
  const value = (mode ?? '').trim()
  if (value === '已开启' || value.toLowerCase() === 'enabled') return '已开启'
  if (value === '未开启' || value.toLowerCase() === 'disabled') return '未开启'
  if (value === '') return '未知'
  return value
}

export function developerModeReady(mode?: string): boolean {
  return developerModeLabel(mode) === '已开启'
}

export function connectionIsUSB(connection?: string): boolean {
  const value = (connection || '').toLowerCase()
  return value === 'usb' || value === 'wired'
}

export function connectionIsNetwork(connection?: string): boolean {
  return (connection || '').toLowerCase() === 'network'
}

export function connectionSupported(connection?: string): boolean {
  return connectionIsUSB(connection) || connectionIsNetwork(connection)
}

export function deviceReady(device?: Device | null): boolean {
  if (!device) return false
  const paired = device.pairing === '已配对'
  return connectionSupported(device.connection) && paired && developerModeReady(device.developerMode)
}

export function deviceInstallReady(device?: Device | null): boolean {
  if (!deviceReady(device)) return false
  if (device?.installServiceReady === false) return false
  return true
}

export function connectionLabel(connection?: string): string {
  if (connectionIsUSB(connection)) return 'USB'
  if (connectionIsNetwork(connection)) return '网络连接'
  return '未知'
}

export function connectionStatusLabel(device?: Device | null): string {
  const label = connectionLabel(device?.connection)
  if (connectionIsNetwork(device?.connection) && deviceInstallReady(device)) return `${label} · 可安装`
  return label
}

export function installBadgeLabel(app?: Pick<ManagedApp, 'installed' | 'validityStatus'> | null): string {
  if (!app?.installed) return '未确认安装'
  if (app.validityStatus === 'expired') return '已失效'
  if (app.validityStatus === 'expiring') return '即将到期'
  return '有效'
}

export function accountTriggerLabel(account: AccountStatus): string {
  if (!account.signedIn) return '登录 Apple ID'
  const selected = account.teams?.find(team => team.id === account.teamID)
  const name = (account.teamName || selected?.name || '').trim()
  return name || '账户与团队'
}

export function signBlockReason(input: {
  environment: Pick<EnvironmentStatus, 'canSign'>
  device?: Device | null
  account: Pick<AccountStatus, 'needsTeam'>
  job?: unknown
}): string {
  if (input.job) return '正在执行任务，请等待完成。'
  if (!input.environment.canSign) return '本机签名环境未就绪。'
  if (input.account.needsTeam) return '请先选择开发团队。'
  if (!input.device) return '未连接 iOS 设备。请连接并解锁设备后刷新。'
  if (!connectionSupported(input.device.connection)) return '无法确认设备连接方式。请刷新设备，未知连接不会视为可用。'
  if (input.device.pairing !== '已配对') return '设备尚未确认配对。请解锁设备、信任这台 Mac 后刷新。'
  if (!developerModeReady(input.device.developerMode)) return '开发者模式未开启。请在设备上开启开发者模式后刷新。'
  if (input.device.installServiceReady === false) return '安装服务当前不可用。请解锁设备并保持 USB 或网络连接后刷新。'
  return ''
}

function formatDate(value?: string): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  }).format(new Date(value))
}

function StatusDot({ok}: {ok: boolean}) {
  return <span className={ok ? 'status-dot ok' : 'status-dot'} aria-hidden="true" />
}

function MenuSelect({
  label, value, options, open, disabled, onToggle, onSelect,
}: {
  label: string
  value: string
  options: {id: string; label: string}[]
  open: boolean
  disabled?: boolean
  onToggle: () => void
  onSelect: (id: string) => void
}) {
  const selected = options.find(option => option.id === value)
  return (
    <div className="menu-root">
      <button className="menu-select" onClick={onToggle} disabled={disabled} aria-haspopup="listbox" aria-expanded={open} aria-label={label}>
        <span>{selected?.label || '未选择'}</span>
        <ChevronDown size={14} />
      </button>
      {open && <div className="menu-panel menu-panel-start" role="listbox" aria-label={label}>
        {options.map(option => (
          <button key={option.id} role="option" aria-selected={option.id === value} onClick={() => onSelect(option.id)}>
            {option.label}
          </button>
        ))}
      </div>}
    </div>
  )
}

function useNarrowChrome(query = '(max-width: 960px)') {
  const [narrow, setNarrow] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const media = window.matchMedia(query)
    const update = () => setNarrow(media.matches)
    update()
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [query])
  return narrow
}

function AppIcon({app, size = 'large'}: {app: ManagedApp; size?: 'small' | 'large'}) {
  if (app.iconDataURL) return <img className={`app-icon ${size}`} src={app.iconDataURL} alt="" />
  return <span className={`app-icon fallback ${size}`}><AppWindow size={size === 'large' ? 34 : 22} /></span>
}

function App() {
  const [environment, setEnvironment] = useState(previewMode ? previewEnvironment : emptyEnvironment)
  const [devices, setDevices] = useState<Device[]>(previewMode ? previewDevices : [])
  const [identities, setIdentities] = useState<SigningIdentity[]>(previewMode ? previewIdentities : [])
  const [selectedDeviceID, setSelectedDeviceID] = useState(previewMode ? 'preview-device' : '')
  const [apps, setApps] = useState<ManagedApp[]>(previewMode ? previewApps : [])
  const [selectedAppID, setSelectedAppID] = useState(previewMode ? 'preview-app' : '')
  const [refreshing, setRefreshing] = useState(!previewMode)
  const [importing, setImporting] = useState(false)
  const [job, setJob] = useState<JobProgress | null>(previewMode && previewParams.has('job') ? {jobID: 'preview', kind: 'renew', step: 'sign', message: '正在按依赖顺序签名', percent: 58} : null)
  const [error, setError] = useState(previewMode && previewParams.has('error') ? '设备连接已中断\n请解锁设备、重新连接后再试。' : '')
  const [notice, setNotice] = useState<Notice | null>(null)
  const [audit, setAudit] = useState<AuditEvent[]>([])
  const [showAudit, setShowAudit] = useState(false)
  const [account, setAccount] = useState<AccountStatus>(previewMode ? previewAccount : {signedIn: false})
  const [login, setLogin] = useState<{open: boolean; authID?: string; appleID: string; password: string; code: string; submitting?: boolean; resendIn: number}>({open: false, appleID: '', password: '', code: '', resendIn: 0})
  const [showReplacementConfirm, setShowReplacementConfirm] = useState(false)
  const [showReissueConfirm, setShowReissueConfirm] = useState(false)
  const [reissueKind, setReissueKind] = useState<'sign' | 'renew'>('sign')
  const [openMenu, setOpenMenu] = useState<OpenMenu>(null)
  const narrowChrome = useNarrowChrome()
  const finishedJobs = useRef(new Set<string>())
  const unfinishedAuditShown = useRef(false)
  const codeRefs = useRef<Array<HTMLInputElement | null>>([])

  const selectedDevice = devices.find(device => device.id === selectedDeviceID)
  const selectedApp = apps.find(app => app.id === selectedAppID) ?? apps[0]

  const loadApps = useCallback(async (deviceID: string) => {
    const result = await ListManagedApps(deviceID) as ManagedApp[]
    setApps(result)
    setSelectedAppID(current => result.some(app => app.id === current) ? current : (result[0]?.id ?? ''))
  }, [])

  const loadAudit = useCallback(async () => {
    try {
      const events = await ListAuditEvents(100) as AuditEvent[]
      setAudit(events)
      if (!unfinishedAuditShown.current) {
        const finished = new Set(events.filter(event => event.stage === 'finish' && event.jobID).map(event => event.jobID))
        if (events.some(event => event.stage === 'start' && event.status === 'started' && event.jobID && !finished.has(event.jobID))) {
          unfinishedAuditShown.current = true
          setNotice({id: 'unfinished-audit', level: 'warning', title: '发现未完成任务', message: '上次任务没有结束记录，请连接设备后刷新并重新回查。'})
        }
      }
    } catch { /* 审计读取失败不阻断主流程 */ }
  }, [])

  const showNotice = useCallback((next: Notice) => {
    setNotice(next)
    window.setTimeout(() => setNotice(current => current?.id === next.id ? null : current), next.level === 'error' ? 9000 : 5000)
  }, [])

  const notifySystemIfBackground = useCallback(async (next: Notice) => {
    try {
      if (!document.hasFocus() && !(await WindowIsMinimised())) {
        await SendNotification({id: next.id, title: next.title, body: next.message})
      }
    } catch { /* 顶部通知始终保留，系统通知不可用时无需阻断 */ }
  }, [])

  const refresh = useCallback(async () => {
    setRefreshing(true)
    setError('')
    try {
      const [env, foundDevices, foundIdentities, accountStatus] = await Promise.all([CheckEnvironment(), ListDevices(), ListSigningIdentities(), GetAppleAccountStatus()])
      setEnvironment(env as EnvironmentStatus)
      setIdentities(foundIdentities as SigningIdentity[])
      setAccount(accountStatus as typeof account)
      const found = foundDevices as Device[]
      setDevices(found)
      const nextDevice = found.some(device => device.id === selectedDeviceID) ? selectedDeviceID : (found[0]?.id ?? '')
      setSelectedDeviceID(nextDevice)
      await loadApps(nextDevice)
      await loadAudit()
    } catch (cause) {
      const message = errorText(cause); setError(message); showNotice({id: `error-${Date.now()}`, level: 'error', title: '刷新失败', message})
    } finally {
      setRefreshing(false)
    }
  }, [loadApps, loadAudit, selectedDeviceID, showNotice])

  useEffect(() => { if (!previewMode) void refresh() }, [])

  useEffect(() => {
    if (previewMode) return
    EventsOn('job:progress', (progress: JobProgress) => setJob(progress))
    EventsOn('job:finished', (finished: JobFinished) => {
      finishedJobs.current.add(finished.jobID)
      setJob(null)
      void loadAudit()
      if (!finished.success) {
        setError(finished.message)
        const next: Notice = {id: `job-${finished.jobID}`, level: 'error', title: '任务失败', message: finished.message, code: finished.code}
        showNotice(next); void notifySystemIfBackground(next)
        if (finished.code === 'bundle_id_unavailable') setShowReplacementConfirm(true)
        if (finished.code === 'signing_identity_missing') {
          setReissueKind(finished.kind === 'renew' ? 'renew' : 'sign')
          setShowReissueConfirm(true)
        }
      } else {
        setError('')
        const next: Notice = {id: `job-${finished.jobID}`, level: 'success', title: '任务完成', message: finished.message}
        showNotice(next); void notifySystemIfBackground(next)
        void loadApps(selectedDeviceID)
      }
    })
    EventsOn('ipa:imported', () => { setImporting(false); void loadApps(selectedDeviceID) })
    EventsOn('ipa:import-failed', (failure: {message?: string}) => {
      const message = failure?.message ?? '导入失败'; setImporting(false); setError(message); showNotice({id: `import-${Date.now()}`, level: 'error', title: '导入失败', message})
    })
    return () => {
      EventsOff('job:progress')
      EventsOff('job:finished')
      EventsOff('ipa:imported')
      EventsOff('ipa:import-failed')
    }
    void loadAudit()
  }, [loadApps, loadAudit, notifySystemIfBackground, selectedDeviceID, showNotice])

  const importIPA = async () => {
    setImporting(true); setError('')
    try {
      const imported = await SelectAndImportIPA() as ManagedApp
      if (imported?.id) {
        showNotice({id: `import-${imported.id}-${Date.now()}`, level: 'success', title: 'IPA 已导入', message: `${imported.name} 已加入托管库`})
        await loadApps(selectedDeviceID)
        setSelectedAppID(imported.id)
      }
    } catch (cause) {
      const message = errorText(cause)
      if (message) { setError(message); showNotice({id: `import-${Date.now()}`, level: 'error', title: '导入失败', message}) }
    } finally { setImporting(false) }
  }

  const start = async (action: 'sign' | 'install' | 'renew', replacement = false, certificatePolicy = 'reuse') => {
    if (!selectedApp || !selectedDeviceID) return
    setError(''); setShowReplacementConfirm(false); setShowReissueConfirm(false)
    try {
      const handle = action === 'sign'
        ? await SignApp(selectedApp.id, selectedDeviceID, replacement ? 'replacement' : (selectedApp.effectiveBundleID === selectedApp.originalBundleID ? 'preserve' : 'existing'), certificatePolicy)
        : action === 'install'
          ? await InstallApp(selectedApp.id, selectedDeviceID)
          : await RenewApp(selectedApp.id, selectedDeviceID, certificatePolicy)
      if (!finishedJobs.current.has(handle.jobID)) {
        setJob({jobID: handle.jobID, kind: action, step: 'start', message: '正在准备任务', percent: 2})
      }
    } catch (cause) { const message = errorText(cause); setError(message); showNotice({id: `action-${Date.now()}`, level: 'error', title: '操作失败', message}) }
  }

  const statusLabel = useMemo(() => installBadgeLabel(selectedApp), [selectedApp])
  const blockReason = useMemo(
    () => signBlockReason({environment, device: selectedDevice, account, job}),
    [account, environment, job, selectedDevice],
  )

  useEffect(() => {
    if (!openMenu) return
    const onPointer = (event: MouseEvent) => {
      if (!(event.target instanceof Element) || event.target.closest('.menu-root')) return
      setOpenMenu(null)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpenMenu(null)
    }
    document.addEventListener('mousedown', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [openMenu])

  const toggleMenu = (menu: Exclude<OpenMenu, null>) => {
    setOpenMenu(current => current === menu ? null : menu)
  }

  const selectTeam = async (teamID: string) => {
    const team = account.teams?.find(item => item.id === teamID)
    await SelectDeveloperTeam(teamID)
    setAccount(current => ({...current, teamID, teamName: team?.name || current.teamName, needsTeam: false}))
    setOpenMenu(null)
  }

  const signOut = async () => {
    setOpenMenu(null)
    await SignOutAppleAccount()
    setAccount({signedIn: false})
    void refresh()
  }

  const openAudit = () => {
    setOpenMenu(null)
    setShowAudit(current => !current)
    void loadAudit()
  }

  const openLogin = async () => {
    try {
      const remembered = await RememberedAppleCredentials() as {appleID?: string; password?: string}
      setLogin(current => ({
        ...current,
        open: true,
        appleID: current.appleID || remembered.appleID || '',
        password: current.password || remembered.password || '',
      }))
    } catch {
      setLogin(current => ({...current, open: true}))
    }
  }

  const submitLogin = async (codeOverride?: string) => {
    setError(''); setLogin(current => ({...current, submitting: true}))
    try {
      if (!login.authID) {
        try {
          await RememberAppleCredentials(login.appleID, login.password)
        } catch (cause) {
          showNotice({id: `remember-${Date.now()}`, level: 'warning', title: '未能记住密码', message: errorText(cause)})
        }
        const challenge = await StartAppleLogin(login.appleID, login.password) as {authID: string; needsTwoFactor: boolean}
        if (!challenge.needsTwoFactor) {
          setAccount(await GetAppleAccountStatus() as typeof account)
          setLogin(current => ({...current, open: false, authID: undefined, code: '', submitting: false, resendIn: 0}))
          showNotice({id: `login-${Date.now()}`, level: 'success', title: 'Apple ID 已登录', message: '账号已记住，登录会话已保存到本机钥匙串'})
          await refresh()
        } else {
          setLogin(current => ({...current, authID: challenge.authID, code: '', submitting: false, resendIn: 30}))
        }
      } else {
        const result = await SubmitTwoFactor(login.authID, codeOverride ?? login.code)
        setAccount(result as typeof account)
        setLogin(current => ({...current, open: false, authID: undefined, code: '', submitting: false, resendIn: 0}))
        showNotice({id: `login-${Date.now()}`, level: 'success', title: 'Apple ID 已登录', message: '账号已记住，登录会话已保存到本机钥匙串'})
        await refresh()
      }
    } catch (cause) { const message = errorText(cause); setError(message); setLogin(current => ({...current, authID: undefined, code: '', submitting: false, resendIn: 0})); showNotice({id: `login-${Date.now()}`, level: 'error', title: '登录失败', message}) }
  }

  useEffect(() => {
    if (!login.open || !login.authID || login.resendIn <= 0) return
    const timer = window.setInterval(() => setLogin(current => ({...current, resendIn: Math.max(0, current.resendIn - 1)})), 1000)
    return () => window.clearInterval(timer)
  }, [login.open, login.authID, login.resendIn])

  const setCodeDigit = (index: number, value: string) => {
    const digits = value.replace(/\D/g, '').slice(0, 6)
    const next = login.code.split(''); while (next.length < 6) next.push('');
    if (digits.length > 1) { digits.split('').forEach((digit, offset) => { if (index + offset < 6) next[index + offset] = digit }); }
    else next[index] = digits
    const code = next.join('').slice(0, 6)
    setLogin(current => ({...current, code}))
    const focus = Math.min(index + digits.length, 5)
    window.setTimeout(() => codeRefs.current[focus]?.focus(), 0)
    if (code.length === 6 && !login.submitting) window.setTimeout(() => void submitLogin(code), 0)
  }

  return (
    <main className="shell">
      <header className="app-chrome">
        <div className="chrome-top">
          <div className="brand"><ShieldCheck size={20} /><strong>续签助手</strong></div>
          <div className="chrome-actions">
            <button className="icon-button" onClick={() => void refresh()} disabled={refreshing || !!job} title="刷新设备和环境" aria-label="刷新设备和环境">
              <RefreshCw size={18} className={refreshing ? 'spin' : ''} />
            </button>
            <div className="menu-root">
              <button
                className="account-button"
                onClick={() => account.signedIn ? toggleMenu('account') : void openLogin()}
                disabled={!!job}
                aria-haspopup={account.signedIn ? 'menu' : undefined}
                aria-expanded={account.signedIn ? openMenu === 'account' : undefined}
                aria-label={account.signedIn ? '账户与团队' : '登录 Apple ID'}
              >
                <span>{accountTriggerLabel(account)}</span>
                {account.signedIn && <ChevronDown size={14} />}
              </button>
              {account.signedIn && openMenu === 'account' && <div className="menu-panel" role="menu" aria-label="账户与团队">
                <div className="menu-section">
                  <strong>已登录 Apple ID</strong>
                  {account.teamName || account.teams?.find(team => team.id === account.teamID)?.name ? <span>{account.teamName || account.teams?.find(team => team.id === account.teamID)?.name}</span> : <span>请选择开发团队</span>}
                </div>
                {(account.teams?.length ?? 0) > 0 && account.teams?.map(team => (
                  <button key={team.id} role="menuitemradio" aria-checked={team.id === account.teamID} onClick={() => void selectTeam(team.id)}>
                    {team.name || team.id}
                  </button>
                ))}
                <button role="menuitem" className="menu-danger" onClick={() => void signOut()}>退出登录</button>
              </div>}
            </div>
            {!narrowChrome && <button className="audit-button" onClick={openAudit} disabled={!!job} aria-pressed={showAudit}>安装审计</button>}
            {narrowChrome && <div className="menu-root more-menu">
              <button className="icon-button" onClick={() => toggleMenu('more')} disabled={!!job} aria-haspopup="menu" aria-expanded={openMenu === 'more'} aria-label="更多">
                <MoreHorizontal size={18} />
              </button>
              {openMenu === 'more' && <div className="menu-panel" role="menu" aria-label="更多">
                <button role="menuitem" onClick={openAudit} disabled={!!job}>安装审计</button>
              </div>}
            </div>}
          </div>
        </div>
        <div className="device-status">
          {selectedDevice ? <>
            <div className="device-identity">
              <Smartphone size={16} />
              {devices.length > 1 ? <MenuSelect
                label="选择设备"
                value={selectedDeviceID}
                options={devices.map(device => ({id: device.id, label: `${device.name} · ${connectionLabel(device.connection)}`}))}
                open={openMenu === 'device'}
                onToggle={() => toggleMenu('device')}
                onSelect={id => { setSelectedDeviceID(id); setOpenMenu(null); void loadApps(id) }}
              /> : <strong>{selectedDevice.name}</strong>}
              <span>· iOS {selectedDevice.osVersion}</span>
            </div>
            <span className="device-meta"><StatusDot ok={deviceInstallReady(selectedDevice)} />{connectionStatusLabel(selectedDevice)}</span>
            <span className="device-meta"><StatusDot ok={selectedDevice.pairing === '已配对'} />{selectedDevice.pairing === '已配对' ? '已配对' : `配对 ${selectedDevice.pairing || '未知'}`}</span>
            <span className="device-meta"><StatusDot ok={developerModeReady(selectedDevice.developerMode)} />开发者模式{developerModeLabel(selectedDevice.developerMode)}</span>
            {identities.length > 1 && <MenuSelect
              label="选择开发身份"
              value={identities.find(identity => identity.selected)?.id ?? ''}
              options={identities.map(identity => ({id: identity.id, label: identity.label}))}
              open={openMenu === 'identity'}
              disabled={!!job}
              onToggle={() => toggleMenu('identity')}
              onSelect={id => {
                void SelectSigningIdentity(id).then(() => {
                  setIdentities(current => current.map(identity => ({...identity, selected: identity.id === id})))
                  setOpenMenu(null)
                })
              }}
            />}
          </> : <div className="device-identity"><Unplug size={16} /><strong>未连接 iOS 设备</strong><span>连接并解锁设备后刷新</span></div>}
        </div>
      </header>

      {notice && <div className={`top-notice ${notice.level}`} role="status"><div><strong>{notice.title}</strong><span>{notice.message}</span>{notice.code && <small>错误码：{notice.code}</small>}</div><button className="icon-button compact" onClick={() => setNotice(null)} aria-label="关闭通知"><X size={16} /></button></div>}

      {!environment.volumeAvailable && <div className="storage-warning"><HardDrive size={17} /><span>{environment.volumeIssue || '应用数据目录不可用，只显示历史状态'}</span></div>}
      {environment.platformSupported === false && environment.platformIssue && <div className="storage-warning platform-warning"><AlertCircle size={17} /><span>{environment.platformIssue}，签名、安装和续签已禁用</span></div>}

      <div className="workspace">
        <aside className="app-list" style={{'--wails-drop-target': 'drop'} as React.CSSProperties}>
          <div className="list-heading"><span>我的应用</span><button className="icon-button compact" onClick={() => void importIPA()} disabled={!environment.canImport || importing || !!job} title="导入 IPA" aria-label="导入 IPA"><Import size={17} /></button></div>
          <div className="list-scroll">
            {apps.map(app => <button key={app.id} className={`app-row ${selectedApp?.id === app.id ? 'selected' : ''}`} onClick={() => setSelectedAppID(app.id)}>
              <AppIcon app={app} size="small" />
              <span className="app-row-copy"><strong>{app.name}</strong><small>{app.version || '版本未知'} · {app.installed ? (app.validityStatus === 'expired' ? '已失效' : '已安装') : app.signed ? '待安装' : '待签名'}</small></span>
              <StatusDot ok={app.installed && app.validityStatus !== 'expired'} />
            </button>)}
            {apps.length === 0 && <button className="drop-empty" onClick={() => void importIPA()} disabled={!environment.canImport || importing}>
              {importing ? <LoaderCircle className="spin" size={24} /> : <Download size={24} />}
              <span>{importing ? '正在导入' : '拖入 IPA 或点击导入'}</span>
            </button>}
          </div>
          <div className="environment-line"><StatusDot ok={environment.canSign} />{environment.canSign ? '本机签名环境就绪' : '签名环境未就绪'}</div>
        </aside>

        <section className="detail">
          {selectedApp ? <>
            <div className="app-heading"><AppIcon app={selectedApp} /><div className="app-title"><h1>{selectedApp.name}</h1><p>版本 {selectedApp.version || '—'} ({selectedApp.buildVersion || '—'})</p></div>
              <span className={`validity ${selectedApp.validityStatus}`}>{statusLabel}</span>
            </div>

            <dl className="metadata">
              <div><dt>Bundle ID</dt><dd>{selectedApp.effectiveBundleID}</dd></div>
              {selectedApp.effectiveBundleID !== selectedApp.originalBundleID && <div><dt>原 Bundle ID</dt><dd>{selectedApp.originalBundleID}</dd></div>}
              <div><dt>签名状态</dt><dd>{selectedApp.signed ? <>已签名 <span>{formatDate(selectedApp.signedAt)}</span></> : '尚未签名'}</dd></div>
              <div><dt>安装状态</dt><dd>{selectedApp.installed ? <>设备已确认 <span>{formatDate(selectedApp.installedAt)}</span></> : '当前设备未确认安装'}</dd></div>
              <div><dt>签名到期</dt><dd>{selectedApp.expirationTime ? <>{formatDate(selectedApp.expirationTime)} <span className="remaining">剩余 {formatRemaining(selectedApp.remainingSeconds)}</span></> : '安装后显示'}</dd></div>
              <div><dt>最低系统</dt><dd>{selectedApp.minimumOS ? `iOS ${selectedApp.minimumOS}` : '未声明'}</dd></div>
            </dl>

            {blockReason && <p className="action-hint">{blockReason}</p>}
            <div className="actions">
              <button className="primary" onClick={() => void start('sign')} disabled={!environment.canSign || !deviceReady(selectedDevice) || !!account.needsTeam || !!job}><ShieldCheck size={17} />{selectedApp.signed ? '重新签名' : '签名'}</button>
              <button onClick={() => void start('install')} disabled={!environment.canInstall || !selectedApp.signed || !deviceInstallReady(selectedDevice) || !!job}><Download size={17} />安装</button>
              <button onClick={() => void start('renew')} disabled={!selectedApp.canRenew || !selectedApp.installed || !deviceInstallReady(selectedDevice) || !!job}><RotateCw size={17} />续签</button>
              <button className="icon-button folder" onClick={() => void RevealSignedIPA(selectedApp.id).catch(cause => setError(errorText(cause)))} disabled={!selectedApp.signed} title="在 Finder 中显示已签名 IPA" aria-label="在 Finder 中显示已签名 IPA"><FolderOpen size={18} /></button>
            </div>
          </> : <div className="no-selection"><AppWindow size={38} /><h1>导入一个 IPA</h1><button onClick={() => void importIPA()} disabled={!environment.canImport}><Import size={17} />选择 IPA</button></div>}

          {error && !notice && <div className="error-panel" role="alert"><AlertCircle size={18} /><pre>{error}</pre><button className="icon-button compact" onClick={() => setError('')} aria-label="关闭错误"><X size={16} /></button></div>}
        </section>

        {showAudit && <aside className="audit-panel"><div className="audit-heading"><strong>安装审计</strong><button className="icon-button compact" onClick={() => setShowAudit(false)} aria-label="关闭安装审计"><X size={16} /></button></div><p className="audit-hint">最近 100 条事件，敏感信息已脱敏。</p><div className="audit-list">{audit.length === 0 ? <div className="audit-empty">暂无审计记录</div> : audit.map(event => <div className="audit-row" key={event.id}><div><strong>{event.kind === 'install' ? '安装' : event.kind === 'renew' ? '续签' : event.kind === 'sign' ? '签名' : '导入'} · {event.stage}</strong><span>{event.message || '—'}</span></div><time>{formatDate(event.at)}</time><em className={event.status === 'success' ? 'ok' : event.status === 'failed' || event.status === 'unknown' ? 'bad' : ''}>{event.status === 'success' ? '成功' : event.status === 'started' ? '进行中' : event.status === 'cancelled' ? '已取消' : event.status === 'unknown' ? '未确认' : '失败'}</em></div>)}</div></aside>}
      </div>

      {job && <div className="job-bar">
        <div className="job-state">{job.percent >= 100 ? <CheckCircle2 size={18} /> : <LoaderCircle size={18} className="spin" />}<div><strong>{job.message}</strong><span>{job.percent}%</span></div></div>
        <div className="progress-track"><span style={{width: `${job.percent}%`}} /></div>
        <button onClick={() => void CancelJob(job.jobID)}><XCircle size={17} />取消</button>
      </div>}

      {showReplacementConfirm && selectedApp && <div className="modal-backdrop" role="presentation">
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby="replacement-title">
          <h2 id="replacement-title">使用替代 Bundle ID？</h2>
          <p>替代签名会作为另一个 App 安装，不能覆盖原 App，也不能沿用原 App 的本地数据。后续续签会固定使用同一个替代 ID。</p>
          <div><button onClick={() => setShowReplacementConfirm(false)}>取消</button><button className="primary" onClick={() => void start('sign', true)}>确认并签名</button></div>
        </div>
      </div>}
      {showReissueConfirm && selectedApp && <div className="modal-backdrop" role="presentation">
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby="reissue-title">
          <h2 id="reissue-title">在这台 Mac 重新签发开发证书？</h2>
          <p>Apple 不会把旧私钥发到这台电脑。用当前登录的 Apple ID 重新获取，只能在这台 Mac 签发一张新的开发证书，并作废账户里现有的开发证书。若私钥还在另一台电脑，请取消并导入 .p12。</p>
          <div><button onClick={() => setShowReissueConfirm(false)}>取消</button><button className="primary" onClick={() => void start(reissueKind, false, 'reissue')}>在这台 Mac 重新签发</button></div>
        </div>
      </div>}
      {login.open && <div className="modal-backdrop"><div className="modal login-modal" role="dialog" aria-modal="true" aria-labelledby="login-title">
        <h2 id="login-title">登录 Apple ID</h2>
        {!login.authID ? <input autoFocus type="email" placeholder="Apple ID 邮箱" value={login.appleID} onChange={event => setLogin(current => ({...current, appleID: event.target.value}))} /> : <><p className="challenge-copy">已发送到受信任设备，请输入验证码</p><div className="code-grid">{Array.from({length: 6}, (_, index) => <input key={index} ref={element => { codeRefs.current[index] = element }} autoFocus={index === 0} inputMode="numeric" maxLength={6} value={login.code[index] ?? ''} disabled={!!login.submitting} onPaste={event => { event.preventDefault(); setCodeDigit(index, event.clipboardData.getData('text')) }} onChange={event => setCodeDigit(index, event.target.value)} onKeyDown={event => { if (event.key === 'Backspace' && !login.code[index]) codeRefs.current[Math.max(index - 1, 0)]?.focus() }} aria-label={`验证码第 ${index + 1} 位`} />)}</div><div className="resend-line">{login.resendIn > 0 ? `${login.resendIn} 秒后可重新发送` : <button className="link-button" onClick={async () => { try { await ResendTwoFactor(login.authID!); setLogin(current => ({...current, resendIn: 30})); showNotice({id: `resend-${Date.now()}`, level: 'success', title: '已重新发送', message: '请查看受信任设备'}) } catch (cause) { showNotice({id: `resend-${Date.now()}`, level: 'warning', title: '无法重新发送', message: errorText(cause)}) } }}>重新发送</button>}</div></>}
        {!login.authID && <input type="password" placeholder="密码" autoComplete="current-password" value={login.password} onChange={event => setLogin(current => ({...current, password: event.target.value}))} />}
        <div><button onClick={() => { if (login.authID) void CancelAppleLogin(login.authID); setLogin(current => ({...current, open: false, authID: undefined, code: '', submitting: false, resendIn: 0})) }}>取消</button>{!login.authID && <button className="primary" onClick={() => void submitLogin()} disabled={!!login.submitting}>发送验证码</button>}</div>
      </div></div>}
    </main>
  )
}

export default App
