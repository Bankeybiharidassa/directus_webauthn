export type LoggerLike = {
  info?: (...args: any[]) => void;
  warn?: (...args: any[]) => void;
  error?: (...args: any[]) => void;
  debug?: (...args: any[]) => void;
};

export type ApiExtensionContext = {
  services?: Record<string, any>;
  getSchema?: () => Promise<any>;
  database?: any;
  knex?: any;
  databaseClient?: any;
  env?: Record<string, string>;
  exceptions?: any;
  logger?: any;
};
