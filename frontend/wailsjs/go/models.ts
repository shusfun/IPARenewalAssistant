export namespace main {
	
	export class AppView {
	    id: string;
	    name: string;
	    version: string;
	    buildVersion: string;
	    originalBundleID: string;
	    effectiveBundleID: string;
	    minimumOS?: string;
	    iconDataURL?: string;
	    // Go type: time
	    importedAt: any;
	    signed: boolean;
	    // Go type: time
	    signedAt?: any;
	    installed: boolean;
	    // Go type: time
	    installedAt?: any;
	    // Go type: time
	    expirationTime?: any;
	    validityStatus: string;
	    remainingSeconds: number;
	    canRenew: boolean;
	
	    static createFrom(source: any = {}) {
	        return new AppView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.version = source["version"];
	        this.buildVersion = source["buildVersion"];
	        this.originalBundleID = source["originalBundleID"];
	        this.effectiveBundleID = source["effectiveBundleID"];
	        this.minimumOS = source["minimumOS"];
	        this.iconDataURL = source["iconDataURL"];
	        this.importedAt = this.convertValues(source["importedAt"], null);
	        this.signed = source["signed"];
	        this.signedAt = this.convertValues(source["signedAt"], null);
	        this.installed = source["installed"];
	        this.installedAt = this.convertValues(source["installedAt"], null);
	        this.expirationTime = this.convertValues(source["expirationTime"], null);
	        this.validityStatus = source["validityStatus"];
	        this.remainingSeconds = source["remainingSeconds"];
	        this.canRenew = source["canRenew"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DeveloperTeam {
	    id: string;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new DeveloperTeam(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	    }
	}
	export class AppleAccountStatus {
	    signedIn: boolean;
	    accountRef?: string;
	    teamID?: string;
	    teamName?: string;
	    needsTeam: boolean;
	    teams?: DeveloperTeam[];
	
	    static createFrom(source: any = {}) {
	        return new AppleAccountStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.signedIn = source["signedIn"];
	        this.accountRef = source["accountRef"];
	        this.teamID = source["teamID"];
	        this.teamName = source["teamName"];
	        this.needsTeam = source["needsTeam"];
	        this.teams = this.convertValues(source["teams"], DeveloperTeam);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuditEvent {
	    id: string;
	    jobID?: string;
	    // Go type: time
	    at: any;
	    kind: string;
	    stage: string;
	    status: string;
	    appID?: string;
	    bundleID?: string;
	    deviceID?: string;
	    errorCode?: string;
	    message?: string;
	
	    static createFrom(source: any = {}) {
	        return new AuditEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.jobID = source["jobID"];
	        this.at = this.convertValues(source["at"], null);
	        this.kind = source["kind"];
	        this.stage = source["stage"];
	        this.status = source["status"];
	        this.appID = source["appID"];
	        this.bundleID = source["bundleID"];
	        this.deviceID = source["deviceID"];
	        this.errorCode = source["errorCode"];
	        this.message = source["message"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Device {
	    id: string;
	    name: string;
	    osVersion: string;
	    connection: string;
	    developerMode: string;
	    pairing?: string;
	    available: boolean;
	    transport?: string;
	    channels?: string[];
	    installServiceReady: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.osVersion = source["osVersion"];
	        this.connection = source["connection"];
	        this.developerMode = source["developerMode"];
	        this.pairing = source["pairing"];
	        this.available = source["available"];
	        this.transport = source["transport"];
	        this.channels = source["channels"];
	        this.installServiceReady = source["installServiceReady"];
	    }
	}
	export class EnvironmentStatus {
	    platformSupported: boolean;
	    platformIssue?: string;
	    volumeAvailable: boolean;
	    volumeIssue?: string;
	    signingBackendReady: boolean;
	    deviceBackendReady: boolean;
	    accountReady: boolean;
	    canImport: boolean;
	    canSign: boolean;
	    canInstall: boolean;
	    identityReady: boolean;
	    identityCount: number;
	    toolsReady: boolean;
	    ready: boolean;
	    issues: string[];
	
	    static createFrom(source: any = {}) {
	        return new EnvironmentStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.platformSupported = source["platformSupported"];
	        this.platformIssue = source["platformIssue"];
	        this.volumeAvailable = source["volumeAvailable"];
	        this.volumeIssue = source["volumeIssue"];
	        this.signingBackendReady = source["signingBackendReady"];
	        this.deviceBackendReady = source["deviceBackendReady"];
	        this.accountReady = source["accountReady"];
	        this.canImport = source["canImport"];
	        this.canSign = source["canSign"];
	        this.canInstall = source["canInstall"];
	        this.identityReady = source["identityReady"];
	        this.identityCount = source["identityCount"];
	        this.toolsReady = source["toolsReady"];
	        this.ready = source["ready"];
	        this.issues = source["issues"];
	    }
	}
	export class JobHandle {
	    jobID: string;
	
	    static createFrom(source: any = {}) {
	        return new JobHandle(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.jobID = source["jobID"];
	    }
	}
	export class LoginChallenge {
	    authID: string;
	    needsTwoFactor: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LoginChallenge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.authID = source["authID"];
	        this.needsTwoFactor = source["needsTwoFactor"];
	        this.message = source["message"];
	    }
	}
	export class RememberedAppleCredentials {
	    appleID?: string;
	    password?: string;
	
	    static createFrom(source: any = {}) {
	        return new RememberedAppleCredentials(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.appleID = source["appleID"];
	        this.password = source["password"];
	    }
	}
	export class SigningIdentityOption {
	    id: string;
	    label: string;
	    selected: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SigningIdentityOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.selected = source["selected"];
	    }
	}

}

