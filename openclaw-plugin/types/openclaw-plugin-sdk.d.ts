declare module "openclaw/plugin-sdk" {
  export interface OpenClawPluginApi {
    pluginConfig?: unknown;
    logger: {
      info(message: string): void;
      warn?(message: string): void;
      error?(message: string): void;
    };
    registerService(service: {
      id: string;
      start(): void | Promise<void>;
      stop(): void | Promise<void>;
    }): void;
    registerCommand(command: {
      name: string;
      description: string;
      acceptsArgs: boolean;
      requireAuth: boolean;
      handler(context: { args?: string }): unknown;
    }): void;
    on(event: string, handler: (event: any, context: any) => unknown): void;
  }
}
