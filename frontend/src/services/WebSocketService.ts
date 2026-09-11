import type { ThreatAlert } from '../types/alert';

export type WebSocketConnectionStatus =
  | 'CONNECTING'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'RECONNECTING'
  | 'CLOSED';

export type AlertHandler = (alert: ThreatAlert) => void;
export type StatusHandler = (status: WebSocketConnectionStatus) => void;

export interface WebSocketConfig {
  url?: string;
  maxReconnectAttempts?: number;
  initialReconnectDelayMs?: number;
  maxReconnectDelayMs?: number;
  maxStoredAlerts?: number;
}

/**
 * WebSocketService manages the real-time alert stream from the backend WS /ws/alerts.
 * Enforces bounded memory, deduplication, exponential backoff reconnects,
 * and strict parsing of standardized threat alert contracts.
 */
export class WebSocketService {
  private socket: WebSocket | null = null;
  private url: string;
  private status: WebSocketConnectionStatus = 'DISCONNECTED';
  private alertListeners = new Set<AlertHandler>();
  private statusListeners = new Set<StatusHandler>();
  private reconnectAttempts = 0;
  private maxReconnectAttempts: number;
  private initialReconnectDelayMs: number;
  private maxReconnectDelayMs: number;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private isExplicitlyClosed = false;
  private seenFlowIds = new Set<string>();
  private recentAlerts: ThreatAlert[] = [];
  private maxStoredAlerts: number;

  constructor(config: WebSocketConfig = {}) {
    const envWsUrl =
      typeof import.meta !== 'undefined'
        ? (import.meta.env?.VITE_WS_URL as string | undefined)
        : undefined;

    this.url = config.url ?? envWsUrl ?? 'ws://localhost:8000/ws/alerts';
    this.maxReconnectAttempts = config.maxReconnectAttempts ?? 10;
    this.initialReconnectDelayMs = config.initialReconnectDelayMs ?? 1000;
    this.maxReconnectDelayMs = config.maxReconnectDelayMs ?? 10000;
    this.maxStoredAlerts = config.maxStoredAlerts ?? 100;
  }

  /**
   * Connect to the WebSocket alerts stream.
   */
  public connect(): void {
    if (typeof WebSocket === 'undefined') {
      // Running in non-browser environment without WebSocket
      return;
    }

    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isExplicitlyClosed = false;
    this.updateStatus('CONNECTING');

    try {
      this.socket = new WebSocket(this.url);

      this.socket.onopen = () => {
        this.reconnectAttempts = 0;
        this.updateStatus('CONNECTED');
      };

      this.socket.onmessage = (event: MessageEvent) => {
        this.handleMessage(event.data);
      };

      this.socket.onerror = () => {
        // Handled through onclose for reconnection
      };

      this.socket.onclose = () => {
        this.socket = null;
        if (this.isExplicitlyClosed) {
          this.updateStatus('CLOSED');
        } else {
          this.updateStatus('DISCONNECTED');
          this.scheduleReconnect();
        }
      };
    } catch {
      this.updateStatus('DISCONNECTED');
      this.scheduleReconnect();
    }
  }

  /**
   * Cleanly disconnect the WebSocket and cease automatic reconnection attempts.
   */
  public disconnect(): void {
    this.isExplicitlyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.updateStatus('CLOSED');
  }

  /**
   * Subscribe to incoming threat alert events.
   * Returns an unsubscribe cleanup function.
   */
  public subscribe(handler: AlertHandler): () => void {
    this.alertListeners.add(handler);
    return () => {
      this.alertListeners.delete(handler);
    };
  }

  /**
   * Subscribe to connection status changes.
   * Immediately invokes the handler with the current status.
   * Returns an unsubscribe cleanup function.
   */
  public onStatusChange(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.status);
    return () => {
      this.statusListeners.delete(handler);
    };
  }

  /**
   * Current connection status.
   */
  public getStatus(): WebSocketConnectionStatus {
    return this.status;
  }

  /**
   * Return recent in-memory alert ring-buffer.
   */
  public getRecentAlerts(): ThreatAlert[] {
    return [...this.recentAlerts];
  }

  /**
   * Process and validate an incoming alert message payload.
   */
  private handleMessage(data: unknown): void {
    if (typeof data !== 'string') {
      return;
    }

    try {
      const parsed = JSON.parse(data);
      // Validate contract fields
      if (!parsed || typeof parsed !== 'object') return;
      if (!parsed.flow_id || !parsed.threat_class || !parsed.severity || parsed.confidence === undefined) {
        return;
      }

      const alert = parsed as ThreatAlert;

      // De-duplicate if identical alert key was recently processed
      const alertKey = `${alert.flow_id}:${alert.threat_class}:${alert.timestamp}`;
      if (this.seenFlowIds.has(alertKey)) {
        return;
      }

      // Bound seenFlowIds set to prevent memory growth
      if (this.seenFlowIds.size >= 500) {
        const oldestKey = this.seenFlowIds.values().next().value;
        if (oldestKey !== undefined) {
          this.seenFlowIds.delete(oldestKey);
        }
      }
      this.seenFlowIds.add(alertKey);

      // Store in bounded ring buffer
      this.recentAlerts.unshift(alert);
      if (this.recentAlerts.length > this.maxStoredAlerts) {
        this.recentAlerts.pop();
      }

      // Broadcast to listeners
      this.alertListeners.forEach((listener) => {
        try {
          listener(alert);
        } catch {
          // Prevent individual listener failures from breaking other listeners
        }
      });
    } catch {
      // Discard invalid JSON payloads
    }
  }

  /**
   * Exponential backoff reconnect scheduler.
   */
  private scheduleReconnect(): void {
    if (this.isExplicitlyClosed) return;
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.updateStatus('DISCONNECTED');
      return;
    }

    this.updateStatus('RECONNECTING');

    const delay = Math.min(
      this.maxReconnectDelayMs,
      this.initialReconnectDelayMs * Math.pow(1.5, this.reconnectAttempts)
    );

    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  private updateStatus(newStatus: WebSocketConnectionStatus): void {
    if (this.status !== newStatus) {
      this.status = newStatus;
      this.statusListeners.forEach((handler) => {
        try {
          handler(newStatus);
        } catch {
          // Protect handler
        }
      });
    }
  }
}

/** Singleton instance of WebSocketService */
export const webSocketService = new WebSocketService();
