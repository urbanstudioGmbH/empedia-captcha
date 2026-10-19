export const TOKEN_FIELD: 'empedia-captcha-token';
export interface Options { sitekey?: string; secret?: string; base?: string; timeoutMs?: number; failOpen?: boolean; fetch?: typeof fetch }
export interface VerifyResult { success: boolean; errorCodes: string[]; unreachable: boolean; raw: Record<string, unknown> }
export interface CheckResult { verdict: 'allow' | 'review' | 'block'; risk: number; reasons: string[]; unreachable: boolean; raw: Record<string, unknown> }
export interface CheckFields { ip?: string; email?: string; name?: string; username?: string; subject?: string; message?: string; honeypot?: string }
export class EmpediaCaptcha {
  constructor(options?: Options);
  static fromEnv(options?: Options, env?: Record<string, string | undefined>): EmpediaCaptcha;
  verify(token: string | undefined | null, action?: string): Promise<VerifyResult>;
  quotaExceeded(): Promise<boolean>;
  check(fields: CheckFields, token?: string): Promise<CheckResult>;
  getToken(action: string, options?: { origin?: string; signals?: Record<string, unknown> }): Promise<string | null>;
  report(kind: 'spam' | 'ham', fields: { email?: string; ip?: string }): Promise<boolean>;
  middleware(options?: { action?: string; onFail?: (req: any, res: any, r: VerifyResult) => void }): (req: any, res: any, next: () => void) => Promise<void>;
  scriptTag(): string;
  widgetTag(action?: string, options?: { mode?: 'focus' | 'load' | 'submit'; badge?: boolean }): string;
}
export default EmpediaCaptcha;
export function solvePow(id: string, bits: number, limit?: number): number;
