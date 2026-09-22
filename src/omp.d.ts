/**
 * Minimal ambient declaration for the omp extension API surface this plugin
 * uses. The real types ship with @oh-my-pi/pi-coding-agent; this shim lets the
 * plugin typecheck standalone.
 */
declare module "@oh-my-pi/pi-coding-agent" {
  export interface ExtensionUIContext {
    notify(message: string, level?: "info" | "warning" | "error"): void;
    setTheme(name: string): Promise<{ success: boolean; error?: string }>;
    setWorkingMessage(text: string): void;
    setTitle?(title: string): void;
    setWidget?(key: string, content: unknown, opts?: unknown): void;
    setStatus?(key: string, text: string): void;
    select?(opts: unknown): Promise<unknown>;
    confirm?(title: string, message: string, opts?: unknown): Promise<boolean>;
    input?(opts: unknown): Promise<string>;
    editor?(opts: unknown): Promise<string>;
    setEditorText?(text: string): void;
    pasteToEditor?(text: string): void;
  }

  export interface ExtensionContext {
    ui: ExtensionUIContext;
    cwd: string;
    hasUI: boolean;
    sessionManager?: { getSessionFile?: () => string | null };
    setInterval(fn: () => void, ms: number): unknown;
    setTimeout(fn: () => void, ms: number): unknown;
    reload(): void;
    [key: string]: unknown;
  }

  export interface ToolCallEvent {
    type: "tool_call";
    toolName: string;
    input: Record<string, unknown>;
    [key: string]: unknown;
  }

  export interface BeforeAgentStartEvent {
    type: "before_agent_start";
    prompt: string;
    images: unknown[];
    systemPrompt: string[];
    [key: string]: unknown;
  }

  export interface GoalUpdatedEvent {
    type: "goal_updated";
    goal: {
      id: string;
      objective: string;
      status: string;
      tokenBudget?: number;
      tokensUsed: number;
      timeUsedSeconds: number;
      createdAt: number;
      updatedAt: number;
    } | null;
    [key: string]: unknown;
  }

  export interface ToolResultEvent {
    type: "tool_result";
    toolName: string;
    toolCallId: string;
    input: Record<string, unknown>;
    content: unknown[];
    isError: boolean;
    details?: unknown;
    [key: string]: unknown;
  }

  export interface ExtensionAPI {
    zod: unknown;
    on(
      event: "before_agent_start",
      handler: (
        event: BeforeAgentStartEvent,
        ctx: ExtensionContext,
      ) =>
        | Promise<{ systemPrompt?: string | string[]; message?: unknown } | undefined>
        | { systemPrompt?: string | string[]; message?: unknown }
        | undefined,
    ): void;
    on(
      event: "tool_call",
      handler: (
        event: ToolCallEvent,
        ctx: ExtensionContext,
      ) =>
        | Promise<{ block?: boolean; reason?: string; input?: Record<string, unknown> } | undefined>
        | { block?: boolean; reason?: string; input?: Record<string, unknown> }
        | undefined,
    ): void;
    on(event: "goal_updated", handler: (event: GoalUpdatedEvent, ctx: ExtensionContext) => unknown): void;
    on(event: "tool_result", handler: (event: ToolResultEvent, ctx: ExtensionContext) => unknown): void;
    on(event: string, handler: (event: never, ctx: ExtensionContext) => unknown): void;
    registerTool(def: {
      name: string;
      label: string;
      description: string;
      parameters: Record<string, unknown>;
      defaultInactive?: boolean;
      execute: (...args: never[]) => unknown;
    }): void;
    registerCommand(
      name: string,
      def: {
        description: string;
        handler: (args: string, ctx: ExtensionContext) => Promise<void> | void;
      },
    ): void;
    getActiveTools(): string[];
    setActiveTools(names: string[]): Promise<void>;
    setSessionName(name: string): void;
    getSessionName(): string;
    sendMessage?(msg: unknown, opts?: unknown): void;
    sendUserMessage?(
      content: string,
      opts?: { deliverAs?: "steer" | "followUp" | "nextTurn" | "aside"; attribution?: "user" | "agent" },
    ): void;
    appendEntry?(customType: string, data?: unknown): void;
    [key: string]: unknown;
  }
}
