import type { ComponentType } from 'react';
export interface EmpediaCaptchaProps { sitekey: string; base: string; action?: string; mode?: 'focus' | 'load' | 'submit'; badge?: boolean; onToken?: (token: string) => void; onError?: (code?: string) => void; className?: string }
export const EmpediaCaptcha: ComponentType<EmpediaCaptchaProps>;
export function loadWidget(base: string): Promise<unknown>;
export function useEmpediaCaptcha(o: { sitekey: string; base: string; action?: string }): { execute: () => Promise<string>; busy: boolean };
export default EmpediaCaptcha;
