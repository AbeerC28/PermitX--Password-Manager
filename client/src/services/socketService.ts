import { io, Socket } from 'socket.io-client';
import { ApprovalRequest } from './requestApi';

// Socket event types
export interface ServerToClientEvents {
  'request-notification': (request: ApprovalRequest) => void;
  'status-update': (request: ApprovalRequest) => void;
  'approval-granted': (request: ApprovalRequest) => void;
  'request-expired': (request: ApprovalRequest) => void;
  'connection-status': (status: { connected: boolean; timestamp: Date }) => void;
}

export interface ClientToServerEvents {
  'join-admin-room': () => void;
  'join-user-room': (email: string) => void;
  'request-created': (request: ApprovalRequest) => void;
}

export type SocketClient = Socket<ServerToClientEvents, ClientToServerEvents>;

export class SocketService {
  private socket: SocketClient | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private connectionStatus: 'connected' | 'disconnected' | 'connecting' | 'error' = 'disconnected';
  private listeners: Map<string, Set<(...args: any[]) => void>> = new Map();

  constructor(private serverUrl: string = 'http://localhost:3000') {}

  // Initialize socket connection
  connect(token?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.socket?.connected) {
        resolve();
        return;
      }

      this.connectionStatus = 'connecting';
      
      const socketOptions: any = {
        transports: ['websocket', 'polling'],
        timeout: 10000,
        forceNew: true,
      };

      // Add auth token if provided
      if (token) {
        socketOptions.auth = { token };
      }

      this.socket = io(this.serverUrl, socketOptions);

      // Connection event handlers
      this.socket.on('connect', () => {
        console.log('Socket connected:', this.socket?.id);
        this.connectionStatus = 'connected';
        this.reconnectAttempts = 0;
        this.emitToListeners('connection-status', { connected: true, timestamp: new Date() });
        resolve();
      });

      this.socket.on('disconnect', (reason) => {
        console.log('Socket disconnected:', reason);
        this.connectionStatus = 'disconnected';
        this.emitToListeners('connection-status', { connected: false, timestamp: new Date() });
        
        // Attempt to reconnect if not manually disconnected
        if (reason !== 'io client disconnect') {
          this.attemptReconnect();
        }
      });

      this.socket.on('connect_error', (error) => {
        console.error('Socket connection error:', error);
        this.connectionStatus = 'error';
        this.emitToListeners('connection-status', { connected: false, timestamp: new Date() });
        
        if (this.reconnectAttempts === 0) {
          reject(error);
        }
      });

      // Set up event listeners for real-time updates
      this.setupEventListeners();
    });
  }

  // Disconnect socket
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connectionStatus = 'disconnected';
      this.listeners.clear();
    }
  }

  // Check if socket is connected
  isConnected(): boolean {
    return this.socket?.connected || false;
  }

  // Get connection status
  getConnectionStatus(): string {
    return this.connectionStatus;
  }

  // Join admin room for notifications
  joinAdminRoom(): void {
    if (this.socket?.connected) {
      this.socket.emit('join-admin-room');
    }
  }

  // Join user room for status updates
  joinUserRoom(email: string): void {
    if (this.socket?.connected) {
      this.socket.emit('join-user-room', email);
    }
  }

  // Emit request created event
  emitRequestCreated(request: ApprovalRequest): void {
    if (this.socket?.connected) {
      this.socket.emit('request-created', request);
    }
  }

  // Add event listener
  on<K extends keyof ServerToClientEvents>(
    event: K,
    listener: ServerToClientEvents[K]
  ): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);

    // Also add to socket if connected
    if (this.socket) {
      this.socket.on(event, listener);
    }
  }

  // Remove event listener
  off<K extends keyof ServerToClientEvents>(
    event: K,
    listener: ServerToClientEvents[K]
  ): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.delete(listener);
      if (eventListeners.size === 0) {
        this.listeners.delete(event);
      }
    }

    // Also remove from socket if connected
    if (this.socket) {
      this.socket.off(event, listener);
    }
  }

  // Set up event listeners on socket
  private setupEventListeners(): void {
    if (!this.socket) return;

    // Set up all registered listeners on the new socket connection
    this.listeners.forEach((listeners, event) => {
      listeners.forEach(listener => {
        this.socket!.on(event as any, listener);
      });
    });
  }

  // Emit to all registered listeners
  private emitToListeners(event: string, ...args: any[]): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(listener => {
        try {
          listener(...args);
        } catch (error) {
          console.error(`Error in socket event listener for ${event}:`, error);
        }
      });
    }
  }

  // Attempt to reconnect
  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.connectionStatus = 'error';
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1); // Exponential backoff

    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms`);

    setTimeout(() => {
      if (this.socket && !this.socket.connected) {
        this.socket.connect();
      }
    }, delay);
  }
}

// Create singleton instance
export const socketService = new SocketService(
  import.meta.env.VITE_SOCKET_URL || 'http://localhost:3000'
);