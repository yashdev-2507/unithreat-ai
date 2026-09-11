import type { DataService } from './DataService';
import { HttpDataService } from './HttpDataService';
import { mockDataService } from './MockDataService';

export * from './DataService';
export * from './HttpDataService';
export * from './MockDataService';
export * from './WebSocketService';
export * from './mockData';

/**
 * Service factory that instantiates either the real HttpDataService or MockDataService.
 *
 * Defaults to REAL HttpDataService for live/integration operations.
 * Uses MockDataService only when explicitly requested via VITE_USE_MOCK === 'true'.
 */
export function createDataService(): DataService {
  const useMock =
    typeof import.meta !== 'undefined' &&
    import.meta.env?.VITE_USE_MOCK === 'true';

  if (useMock) {
    return mockDataService;
  }
  return new HttpDataService();
}

/** Default active application data service */
export const defaultDataService: DataService = createDataService();
