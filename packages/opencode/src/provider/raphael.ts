import {
  type LanguageModelV3,
  type LanguageModelV3StreamCallSettings,
  type LanguageModelV3CallSettings,
} from "@ai-sdk/provider"

const RAPHAEL_ORCHESTRATOR_DEFAULT = "http://localhost:8080"

interface RaphaelModelConfig {
  orchestratorUrl: string
  apiKey?: string
  target?: string
  mode?: string
}

function getConfig(): RaphaelModelConfig {
  return {
    orchestratorUrl: process.env.RAPHAEL_ORCHESTRATOR_URL || RAPHAEL_ORCHESTRATOR_DEFAULT,
    apiKey: process.env.RAPHAEL_API_KEY,
    target: process.env.RAPHAEL_TARGET,
    mode: process.env.RAPHAEL_MODE || "autonomous",
  }
}

class RaphaelLanguageModel implements LanguageModelV3 {
  readonly specificationVersion = "v3"
  readonly provider = "raphael"
  readonly modelId: string
  private config: RaphaelModelConfig

  constructor(modelId: string, config?: Partial<RaphaelModelConfig>) {
    this.modelId = modelId
    this.config = { ...getConfig(), ...config }
  }

  async doStream(settings: LanguageModelV3StreamCallSettings) {
    const url = `${this.config.orchestratorUrl}/api/agent/execute`
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.config.apiKey ? { Authorization: `Bearer ${this.config.apiKey}` } : {}),
      },
      body: JSON.stringify({
        messages: settings.messages,
        tools: settings.tools,
        target: this.config.target,
        mode: this.config.mode,
        model: this.modelId,
      }),
    })
    if (!response.ok) {
      const text = await response.text().catch(() => "unknown error")
      throw new Error(`Raphael orchestrator error (${response.status}): ${text}`)
    }
    const reader = response.body?.getReader()
    if (!reader) throw new Error("Raphael orchestrator returned no body")
    const decoder = new TextDecoder()
    const stream = new ReadableStream<string>({
      async pull(controller) {
        while (true) {
          const { done, value } = await reader.read()
          if (done) { controller.close(); return }
          const chunk = decoder.decode(value, { stream: true })
          for (const line of chunk.split("\n").filter(Boolean)) {
            if (line.startsWith("data: ")) controller.enqueue(line.slice(6))
          }
        }
      },
      cancel() { reader.cancel().catch(() => {}) },
    })
    return {
      stream,
      response: { id: `raphael-${Date.now()}`, timestamp: new Date(), modelId: this.modelId },
    }
  }

  async doGenerate(settings: LanguageModelV3CallSettings) {
    const url = `${this.config.orchestratorUrl}/api/agent/execute`
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.config.apiKey ? { Authorization: `Bearer ${this.config.apiKey}` } : {}),
      },
      body: JSON.stringify({
        messages: settings.messages,
        tools: settings.tools,
        target: this.config.target,
        mode: this.config.mode,
        model: this.modelId,
        stream: false,
      }),
    })
    if (!response.ok) {
      const text = await response.text().catch(() => "unknown error")
      throw new Error(`Raphael orchestrator error (${response.status}): ${text}`)
    }
    const data = await response.json()
    return {
      text: data.content ?? data.text ?? "",
      response: { id: data.id ?? `raphael-${Date.now()}`, timestamp: new Date(), modelId: this.modelId },
      usage: data.usage ?? { promptTokens: 0, completionTokens: 0 },
      finishReason: data.finishReason ?? "stop",
    }
  }
}

export function createRaphael(options?: Partial<RaphaelModelConfig>) {
  const create = (modelId: string) => new RaphaelLanguageModel(modelId, options)
  create.languageModel = (modelId: string) => new RaphaelLanguageModel(modelId, options)
  return create
}
