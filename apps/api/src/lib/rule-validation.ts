import net from 'node:net';

import { z } from 'zod';

/**
 * Shared validation for policy rules and policy template rules, applied at the route boundary
 * so invalid values never reach the compiler (and never get interpolated into firewall configs).
 */

export const PORTS_REGEX = /^(\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$/;
export const PORTS_MESSAGE = 'Invalid port format. Use: 80, 80,443, or 8000-9000 (ports 1-65535)';

/** Linux interface names: max 15 chars, no whitespace/quotes. */
export const INTERFACE_NAME_REGEX = /^[A-Za-z0-9_.:@-]{1,15}$/;
/** Interface roles are labels matched against host_interfaces.role. */
export const INTERFACE_ROLE_REGEX = /^[A-Za-z0-9_.-]{1,64}$/;

export const protocolSchema = z.enum(['tcp', 'udp', 'icmp', 'any']);
export const sourceTypeSchema = z.enum(['CIDR', 'TAG', 'VLAN', 'HOST']);
export const interfaceScopeTypeSchema = z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']);
export const interfaceNamesSchema = z.array(z.string().regex(INTERFACE_NAME_REGEX, 'Invalid interface name'));
export const interfaceRolesSchema = z.array(z.string().regex(INTERFACE_ROLE_REGEX, 'Invalid interface role'));
/** Rule comments end up in firewall configs: keep them single-line and free of quotes/backslashes. */
export const ruleCommentSchema = z
  .string()
  .max(255, 'Comment must be at most 255 characters')
  .regex(/^[^"\\\r\n`$]*$/, 'Comment must not contain quotes, backslashes, backticks, $ or line breaks');

/** True when every port/range is within 1-65535 and ranges are ascending. */
export function portsInRange(ports: string): boolean {
  for (const part of ports.split(',')) {
    const [a, b] = part.split('-').map((x) => Number(x));
    if (!Number.isInteger(a) || a < 1 || a > 65535) return false;
    if (b !== undefined) {
      if (!Number.isInteger(b) || b < 1 || b > 65535 || b < a) return false;
    }
  }
  return true;
}

export const portsSchema = z
  .string()
  .regex(PORTS_REGEX, PORTS_MESSAGE)
  .refine(portsInRange, PORTS_MESSAGE);

/** IPv4/IPv6 address or CIDR with a valid prefix length. */
export function isIpOrCidr(value: string): boolean {
  const [addr, prefix, ...rest] = value.trim().split('/');
  if (rest.length > 0) return false;
  const family = net.isIP(addr);
  if (!family) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const p = Number(prefix);
  return family === 4 ? p >= 0 && p <= 32 : p >= 0 && p <= 128;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type RuleSemanticsInput = {
  protocol?: string | null;
  ports?: string | null;
  sourceType?: string | null;
  sourceValue?: string | null;
};

/**
 * Cross-field validation. Returns a list of human-readable problems (empty = valid).
 * Pass the *effective* rule (merged with existing values on partial updates).
 */
export function validateRuleSemantics(rule: RuleSemanticsInput): string[] {
  const problems: string[] = [];
  const ports = rule.ports ?? '';
  if (ports !== '') {
    if (!PORTS_REGEX.test(ports) || !portsInRange(ports)) problems.push(PORTS_MESSAGE);
    if (rule.protocol === 'any' || rule.protocol === 'icmp') {
      problems.push(`Ports cannot be specified when protocol is '${rule.protocol}'. Use tcp or udp, or clear the ports.`);
    }
  }
  if (rule.sourceType && rule.sourceValue !== undefined && rule.sourceValue !== null) {
    const value = String(rule.sourceValue).trim();
    if (rule.sourceType === 'CIDR') {
      if (!isIpOrCidr(value)) problems.push(`Source value '${value}' is not a valid IP address or CIDR`);
    } else if (['TAG', 'VLAN', 'HOST'].includes(rule.sourceType)) {
      if (!UUID_REGEX.test(value)) problems.push(`Source value for ${rule.sourceType} must be the ${rule.sourceType.toLowerCase()} id (uuid)`);
    }
  }
  return problems;
}
