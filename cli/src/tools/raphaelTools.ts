import { Tool } from '../Tool.js'

const RAPHAEL_URL = process.env.RAPHAEL_ORCHESTRATOR_URL || 'http://localhost:8080'

async function callTool(endpoint: string, params: any) {
  const response = await fetch(`${RAPHAEL_URL}/api/tools/${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(process.env.RAPHAEL_API_KEY ? { 'X-API-Key': process.env.RAPHAEL_API_KEY } : {}),
    },
    body: JSON.stringify(params),
  })
  if (!response.ok) {
    throw new Error(`Tool ${endpoint} failed: ${response.status}`)
  }
  return await response.json()
}

export const nmapTool: Tool = {
  name: 'nmap',
  description: 'Port scan, service detection, OS fingerprinting',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'Target IP, domain, or CIDR' },
      ports: { type: 'string', description: 'Port range (e.g., 1-1000)' },
      stealth: { type: 'boolean', description: 'Use stealth scanning' },
      aggressive: { type: 'boolean', description: 'Aggressive scan (faster)' },
    },
    required: ['target'],
  },
  execute: async (params: any) => callTool('nmap', params),
}

export const sqlmapTool: Tool = {
  name: 'sqlmap',
  description: 'Automated SQL injection detection and exploitation',
  parameters: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Target URL' },
      data: { type: 'string', description: 'POST data' },
      dbms: { type: 'string', enum: ['mysql', 'postgresql', 'oracle', 'mssql'] },
      risk: { type: 'number', description: 'Risk level (1-3)' },
    },
    required: ['url'],
  },
  execute: async (params: any) => callTool('sqlmap', params),
}

export const bloodhoundTool: Tool = {
  name: 'bloodhound',
  description: 'Active Directory enumeration and attack path analysis',
  parameters: {
    type: 'object',
    properties: {
      domain: { type: 'string', description: 'Domain to enumerate' },
      collectors: { type: 'array', items: { type: 'string' }, description: 'List of collectors' },
    },
    required: ['domain'],
  },
  execute: async (params: any) => callTool('bloodhound', params),
}

export const metasploitTool: Tool = {
  name: 'metasploit',
  description: 'Metasploit framework for exploitation and post-exploitation',
  parameters: {
    type: 'object',
    properties: {
      module: { type: 'string', description: 'Full module path (e.g., exploit/windows/smb/ms17_010_eternalblue)' },
      payload: { type: 'string', description: 'Payload (e.g., windows/meterpreter/reverse_tcp)' },
      rhost: { type: 'string', description: 'Target IP' },
      lhost: { type: 'string', description: 'Listener IP' },
      options: { type: 'object', description: 'Additional options' },
    },
    required: ['module', 'rhost'],
  },
  execute: async (params: any) => callTool('metasploit', params),
}

export const crackmapexecTool: Tool = {
  name: 'crackmapexec',
  description: 'Credential spraying, SMB enumeration, lateral movement',
  parameters: {
    type: 'object',
    properties: {
      target: { type: 'string', description: 'Target IP or CIDR' },
      username: { type: 'string', description: 'Username or file with usernames' },
      password: { type: 'string', description: 'Password or hash' },
      protocol: { type: 'string', enum: ['smb', 'ssh', 'winrm', 'ldap'], description: 'Protocol to use' },
    },
    required: ['target', 'protocol'],
  },
  execute: async (params: any) => callTool('crackmapexec', params),
}

export const chiselTool: Tool = {
  name: 'chisel',
  description: 'Tunneling and port forwarding over HTTP/HTTPS',
  parameters: {
    type: 'object',
    properties: {
      mode: { type: 'string', enum: ['client', 'server'], description: 'Run as client or server' },
      target: { type: 'string', description: 'Remote server address' },
      port: { type: 'number', description: 'Port to forward' },
      socks: { type: 'boolean', description: 'Enable SOCKS5 proxy' },
    },
    required: ['mode'],
  },
  execute: async (params: any) => callTool('chisel', params),
}

export const raphaelTools = [nmapTool, sqlmapTool, bloodhoundTool, metasploitTool, crackmapexecTool, chiselTool]