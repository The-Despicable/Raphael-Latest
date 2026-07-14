import { Effect, Schema } from "effect"
import * as Tool from "./tool"

const RAPHAEL_URL = process.env.RAPHAEL_ORCHESTRATOR_URL || "http://localhost:8080"

function raphaelRequest(endpoint: string, body: Record<string, unknown>) {
  return Effect.gen(function* () {
    const response = yield* Effect.promise(() =>
      fetch(`${RAPHAEL_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    )
    if (!response.ok) {
      const text = yield* Effect.promise(() => response.text())
      return yield* Effect.die(new Error(`Raphael API error (${response.status}): ${text}`))
    }
    return yield* Effect.promise<unknown>(() => response.json())
  })
}

const NmapParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP, domain, or CIDR range" }),
  ports: Schema.optional(Schema.String).annotate({ description: "Port range, e.g., '22,80,443' or '1-1000'" }),
  aggressive: Schema.optional(Schema.Boolean).annotate({ description: "Enable aggressive scan techniques" }),
})

export const NmapTool = Tool.define(
  "nmap",
  Effect.gen(function* () {
    return {
      description: "Scan a target for open ports, running services, and OS fingerprinting",
      parameters: NmapParameters,
      execute: (params: Schema.Schema.Type<typeof NmapParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/nmap", {
            target: params.target, ports: params.ports, aggressive: params.aggressive,
          })
          return { title: `nmap scan: ${params.target}`, output: JSON.stringify(result, null, 2), metadata: { target: params.target } }
        }).pipe(Effect.orDie),
    }
  }),
)

const SqlmapParameters = Schema.Struct({
  url: Schema.String.annotate({ description: "Target URL with potentially injectable parameter" }),
  data: Schema.optional(Schema.String).annotate({ description: "POST data body if applicable" }),
  level: Schema.optional(Schema.Number).annotate({ description: "Test level (1-5), higher is more thorough" }),
  risk: Schema.optional(Schema.Number).annotate({ description: "Risk level (1-3), higher may cause disruption" }),
})

export const SqlmapTool = Tool.define(
  "sqlmap",
  Effect.gen(function* () {
    return {
      description: "Automated SQL injection detection and exploitation",
      parameters: SqlmapParameters,
      execute: (params: Schema.Schema.Type<typeof SqlmapParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/sqlmap", {
            url: params.url, data: params.data, level: params.level ?? 3, risk: params.risk ?? 2,
          })
          return { title: `sqlmap: ${params.url}`, output: JSON.stringify(result, null, 2), metadata: { url: params.url } }
        }).pipe(Effect.orDie),
    }
  }),
)

const BloodhoundParameters = Schema.Struct({
  domain: Schema.String.annotate({ description: "Active Directory domain to enumerate" }),
  collectors: Schema.optional(Schema.Array(Schema.String).annotate({ description: "BloodHound collectors to run" })),
})

export const BloodhoundTool = Tool.define(
  "bloodhound",
  Effect.gen(function* () {
    return {
      description: "Active Directory enumeration and attack path analysis via BloodHound",
      parameters: BloodhoundParameters,
      execute: (params: Schema.Schema.Type<typeof BloodhoundParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/bloodhound", {
            domain: params.domain, collectors: params.collectors,
          })
          return { title: `bloodhound: ${params.domain}`, output: JSON.stringify(result, null, 2), metadata: { domain: params.domain } }
        }).pipe(Effect.orDie),
    }
  }),
)

const MetasploitParameters = Schema.Struct({
  module: Schema.String.annotate({ description: "Metasploit module path, e.g. 'exploit/multi/handler'" }),
  payload: Schema.optional(Schema.String).annotate({ description: "Payload to use" }),
  options: Schema.optional(Schema.Record(Schema.String, Schema.String).annotate({ description: "Module options (LHOST, RHOSTS, etc.)" })),
})

export const MetasploitTool = Tool.define(
  "metasploit",
  Effect.gen(function* () {
    return {
      description: "Metasploit framework — exploit, payload, and post-exploitation modules",
      parameters: MetasploitParameters,
      execute: (params: Schema.Schema.Type<typeof MetasploitParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/metasploit", {
            module: params.module, payload: params.payload, options: params.options,
          })
          return { title: `msf: ${params.module}`, output: JSON.stringify(result, null, 2), metadata: { module: params.module } }
        }).pipe(Effect.orDie),
    }
  }),
)

const CrackMapExecParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Target IP or CIDR range" }),
  protocol: Schema.Literals(["smb", "ssh", "winrm", "ldap", "mssql"]).annotate({ description: "Protocol to attack" }),
  username: Schema.optional(Schema.String).annotate({ description: "Username or file path" }),
  password: Schema.optional(Schema.String).annotate({ description: "Password or NTLM hash" }),
})

export const CrackMapExecTool = Tool.define(
  "crackmapexec",
  Effect.gen(function* () {
    return {
      description: "Credential spraying, SMB enumeration, and lateral movement via CrackMapExec / NetExec",
      parameters: CrackMapExecParameters,
      execute: (params: Schema.Schema.Type<typeof CrackMapExecParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/crackmapexec", {
            target: params.target, protocol: params.protocol, username: params.username, password: params.password,
          })
          return { title: `cme ${params.protocol}: ${params.target}`, output: JSON.stringify(result, null, 2), metadata: { target: params.target, protocol: params.protocol } }
        }).pipe(Effect.orDie),
    }
  }),
)

const ChiselParameters = Schema.Struct({
  action: Schema.Literals(["client", "server"]).annotate({ description: "Chisel mode" }),
  remote: Schema.String.annotate({ description: "Remote address for reverse tunnel" }),
  local: Schema.optional(Schema.String).annotate({ description: "Local port forwarding spec" }),
})

export const ChiselTool = Tool.define(
  "chisel",
  Effect.gen(function* () {
    return {
      description: "Tunneling and port forwarding via Chisel over HTTP",
      parameters: ChiselParameters,
      execute: (params: Schema.Schema.Type<typeof ChiselParameters>) =>
        Effect.gen(function* () {
          const result = yield* raphaelRequest("/api/tools/chisel", {
            action: params.action, remote: params.remote, local: params.local,
          })
          return { title: `chisel ${params.action}: ${params.remote}`, output: JSON.stringify(result, null, 2), metadata: { action: params.action, remote: params.remote } }
        }).pipe(Effect.orDie),
    }
  }),
)
