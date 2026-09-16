import {afterEach, describe, expect, it, vi} from 'vitest'
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import {
  accountTriggerLabel,
  connectionLabel,
  connectionStatusLabel,
  developerModeLabel,
  developerModeReady,
  deviceInstallReady,
  deviceReady,
  formatRemaining,
  installBadgeLabel,
  signBlockReason,
} from './App'
import {EventsOn} from '../wailsjs/runtime/runtime'

const go = vi.hoisted(() => ({
  CancelAppleLogin: vi.fn(),
  CancelJob: vi.fn(),
  CheckEnvironment: vi.fn(),
  GetAppleAccountStatus: vi.fn(),
  ImportIPA: vi.fn(),
  InstallApp: vi.fn(),
  ListAuditEvents: vi.fn(),
  ListDevices: vi.fn(),
  ListManagedApps: vi.fn(),
  ListSigningIdentities: vi.fn(),
  RememberAppleCredentials: vi.fn(),
  RememberedAppleCredentials: vi.fn(),
  RenewApp: vi.fn(),
  ResendTwoFactor: vi.fn(),
  RevealSignedIPA: vi.fn(),
  SelectAndImportIPA: vi.fn(),
  SelectDeveloperTeam: vi.fn(),
  SelectSigningIdentity: vi.fn(),
  SignApp: vi.fn(),
  SignOutAppleAccount: vi.fn(),
  StartAppleLogin: vi.fn(),
  SubmitTwoFactor: vi.fn(),
}))

vi.mock('../wailsjs/go/main/App', () => go)
vi.mock('../wailsjs/runtime/runtime', () => ({
  EventsOn: vi.fn(),
  EventsOff: vi.fn(),
  SendNotification: vi.fn(),
  WindowIsMinimised: vi.fn(async () => false),
}))

const readyEnvironment = {
  platformSupported: true, volumeAvailable: true, signingBackendReady: true, deviceBackendReady: true,
  accountReady: true, canImport: true, canSign: true, canInstall: true, identityReady: true,
  identityCount: 1, toolsReady: true, ready: true, issues: [] as string[],
}

const usbDevice = {id: 'd', name: 'iPhone', osVersion: '27.0', connection: 'USB', developerMode: '已开启', pairing: '已配对', available: true}

function stubMatchMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches,
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }),
  })
}

function stubRefresh(overrides?: {
  devices?: typeof usbDevice[]
  identities?: {id: string; label: string; selected: boolean}[]
  account?: {signedIn: boolean; teamID?: string; teamName?: string; needsTeam?: boolean; teams?: {id: string; name: string}[]}
  apps?: Array<Record<string, unknown>>
}) {
  go.CheckEnvironment.mockResolvedValue(readyEnvironment)
  go.ListDevices.mockResolvedValue(overrides?.devices ?? [{...usbDevice, connection: 'network', available: false}])
  go.ListSigningIdentities.mockResolvedValue(overrides?.identities ?? [])
  go.GetAppleAccountStatus.mockResolvedValue(overrides?.account ?? {
    signedIn: true, teamID: 'TEAM1', teamName: '示例团队', needsTeam: false,
    teams: [{id: 'TEAM1', name: '示例团队'}, {id: 'TEAM2', name: '另一个团队'}],
  })
  go.ListManagedApps.mockResolvedValue(overrides?.apps ?? [{
    id: 'app', name: '示例应用', version: '1.0', buildVersion: '1', originalBundleID: 'a.b', effectiveBundleID: 'a.b',
    importedAt: new Date().toISOString(), signed: true, installed: false, validityStatus: 'unsigned', remainingSeconds: 0, canRenew: false,
  }])
  go.ListAuditEvents.mockResolvedValue([])
  go.SignOutAppleAccount.mockResolvedValue(undefined)
  go.SelectDeveloperTeam.mockResolvedValue(undefined)
}

describe('formatRemaining', () => {
  it('formats valid, expiring and expired durations', () => {
    expect(formatRemaining(8 * 86400 + 2 * 3600)).toBe('8 天 2 小时')
    expect(formatRemaining(71 * 3600)).toBe('2 天 23 小时')
    expect(formatRemaining(-1)).toBe('已过期')
  })
})

describe('device readiness', () => {
  it('treats 已开启 as ready and 未知 as not ready', () => {
    expect(developerModeLabel('已开启')).toBe('已开启')
    expect(developerModeReady('已开启')).toBe(true)
    expect(developerModeReady('enabled')).toBe(true)
    expect(developerModeReady('未知')).toBe(false)
    expect(developerModeLabel('未知')).toBe('未知')
  })

  it('accepts USB or Network when paired with developer mode', () => {
    expect(deviceReady(usbDevice)).toBe(true)
    expect(deviceReady({...usbDevice, developerMode: '未知'})).toBe(false)
    expect(deviceReady({...usbDevice, pairing: '未知'})).toBe(false)
    expect(deviceReady({...usbDevice, connection: 'network'})).toBe(true)
    expect(deviceReady({...usbDevice, connection: 'unknown'})).toBe(false)
    expect(deviceInstallReady({...usbDevice, connection: 'network', installServiceReady: false})).toBe(false)
  })
})

describe('connection and install labels', () => {
  it('maps network transports to 网络连接 and keeps unknown as 未知', () => {
    expect(connectionLabel('USB')).toBe('USB')
    expect(connectionLabel('wired')).toBe('USB')
    expect(connectionLabel('network')).toBe('网络连接')
    expect(connectionLabel('Network')).toBe('网络连接')
    expect(connectionLabel('unknown')).toBe('未知')
    expect(connectionStatusLabel({...usbDevice, connection: 'network'})).toBe('网络连接 · 可安装')
  })

  it('does not call an unconfirmed install 未安装', () => {
    expect(installBadgeLabel({installed: false, validityStatus: 'unsigned'})).toBe('未确认安装')
    expect(installBadgeLabel({installed: false, validityStatus: 'unsigned'})).not.toBe('未安装')
    expect(installBadgeLabel({installed: true, validityStatus: 'expiring'})).toBe('即将到期')
  })

  it('shows a short team name on the account trigger', () => {
    expect(accountTriggerLabel({signedIn: false})).toBe('登录 Apple ID')
    expect(accountTriggerLabel({signedIn: true, teamID: 'TEAM1', teamName: '示例团队'})).toBe('示例团队')
    expect(accountTriggerLabel({signedIn: true, needsTeam: true})).toBe('账户与团队')
  })
})

describe('signBlockReason', () => {
  const base = {environment: {canSign: true}, device: usbDevice, account: {needsTeam: false}, job: null}

  it('allows a ready network connection and explains unknown connections', () => {
    expect(signBlockReason({...base, device: {...usbDevice, connection: 'network'}})).toBe('')
    expect(signBlockReason({...base, device: {...usbDevice, connection: 'unknown'}})).toBe('无法确认设备连接方式。请刷新设备，未知连接不会视为可用。')
  })

  it('keeps local environment readiness separate from device USB', () => {
    expect(signBlockReason(base)).toBe('')
    expect(signBlockReason({...base, environment: {canSign: false}})).toBe('本机签名环境未就绪。')
    expect(signBlockReason({...base, account: {needsTeam: true}})).toBe('请先选择开发团队。')
    expect(signBlockReason({...base, job: {jobID: '1'}})).toBe('正在执行任务，请等待完成。')
  })
})

describe('chrome interactions', () => {
  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
    stubMatchMedia(false)
  })

  it('does not sign out when the signed-in account button is clicked', async () => {
    stubMatchMedia(false)
    stubRefresh()
    const {default: App} = await import('./App')
    render(<App />)
    const account = await screen.findByRole('button', {name: '账户与团队'})
    fireEvent.click(account)
    expect(go.SignOutAppleAccount).not.toHaveBeenCalled()
    expect(await screen.findByRole('menuitem', {name: '退出登录'})).toBeInTheDocument()
    fireEvent.click(screen.getByRole('menuitem', {name: '退出登录'}))
    await waitFor(() => expect(go.SignOutAppleAccount).toHaveBeenCalledTimes(1))
  })

  it('asks to reissue when the local signing identity is missing', async () => {
    stubMatchMedia(false)
    stubRefresh({devices: [usbDevice]})
    go.SignApp.mockResolvedValue({jobID: 'retry'})
    const {default: App} = await import('./App')
    render(<App />)
    await screen.findByRole('button', {name: '重新签名'})
    const finishedCalls = vi.mocked(EventsOn).mock.calls.filter(call => call[0] === 'job:finished')
    const finished = finishedCalls[finishedCalls.length - 1]?.[1] as (event: {jobID: string; kind: string; success: boolean; message: string; code?: string}) => void
    finished({jobID: '1', kind: 'sign', success: false, message: '本机没有匹配的私钥', code: 'signing_identity_missing'})
    expect(await screen.findByRole('heading', {name: '在这台 Mac 重新签发开发证书？'})).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', {name: '取消'}))
    expect(go.SignApp).not.toHaveBeenCalled()
    finished({jobID: '3', kind: 'sign', success: false, message: '本机没有匹配的私钥', code: 'signing_identity_missing'})
    fireEvent.click(await screen.findByRole('button', {name: '在这台 Mac 重新签发'}))
    await waitFor(() => expect(go.SignApp).toHaveBeenCalledWith('app', 'd', 'preserve', 'reissue'))
  })

  it('shows a network connection as installable without requiring USB', async () => {
    stubMatchMedia(false)
    stubRefresh()
    const {default: App} = await import('./App')
    render(<App />)
    expect(await screen.findByText('网络连接 · 可安装')).toBeInTheDocument()
    expect(screen.getByRole('button', {name: '重新签名'})).toBeEnabled()
    expect(screen.getByText('本机签名环境就绪')).toBeInTheDocument()
    expect(screen.getByText('未确认安装')).toBeInTheDocument()
    expect(screen.queryByText('未安装')).not.toBeInTheDocument()
    expect(screen.queryByText('当前为网络连接，本工具的签名安装流程需要 USB。请连接数据线并刷新设备。')).not.toBeInTheDocument()
  })

  it('opens a React device menu instead of a native select', async () => {
    stubMatchMedia(false)
    stubRefresh({
      devices: [
        usbDevice,
        {id: 'd2', name: 'iPad Pro', osVersion: '18.6', connection: 'USB', developerMode: '已开启', pairing: '已配对', available: true},
      ],
      identities: [
        {id: 'id1', label: 'Apple Development: One', selected: true},
        {id: 'id2', label: 'Apple Development: Two', selected: false},
      ],
    })
    const {default: App} = await import('./App')
    render(<App />)
    const device = await screen.findByRole('button', {name: '选择设备'})
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    fireEvent.click(device)
    expect(screen.getByRole('option', {name: 'iPad Pro · USB'})).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', {name: '选择开发身份'}))
    expect(screen.getByRole('option', {name: 'Apple Development: Two'})).toBeInTheDocument()
    expect(screen.queryByRole('option', {name: 'iPad Pro · USB'})).not.toBeInTheDocument()
  })

  it('keeps 安装审计 available from the more menu when the chrome is narrow', async () => {
    stubMatchMedia(true)
    stubRefresh()
    const {default: App} = await import('./App')
    render(<App />)
    await screen.findByRole('button', {name: '账户与团队'})
    expect(screen.queryByRole('button', {name: '安装审计'})).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', {name: '更多'}))
    expect(screen.getByRole('menuitem', {name: '安装审计'})).toBeInTheDocument()
  })
})
