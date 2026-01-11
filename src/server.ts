import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { config, DatabaseConnection, RedisConnection } from './config';
import { notificationScheduler, expirationService } from './services';
import { initializeSocketService } from './services/socketService';
import userRoutes from './routes/userRoutes';
import requestRoutes from './routes/requestRoutes';
import passwordRoutes from './routes/passwordRoutes';
import adminRoutes from './routes/adminRoutes';

class Server {
  private app: express.Application;
  private httpServer: any;
  private io: SocketIOServer;
  private socketService: any;

  constructor() {
    this.app = express();
    this.httpServer = createServer(this.app);
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: config.corsOrigin,
        methods: ['GET', 'POST'],
        credentials: true,
      },
      transports: ['websocket', 'polling'],
      pingTimeout: 60000,
      pingInterval: 25000,
    });

    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeSocketIO();
  }

  private initializeMiddleware(): void {
    // Security middleware
    this.app.use(helmet());

    // CORS middleware
    this.app.use(
      cors({
        origin: config.corsOrigin,
        credentials: true,
      })
    );

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: config.nodeEnv,
      });
    });
  }

  private initializeRoutes(): void {
    // Mount API routes
    this.app.use('/api/admin', adminRoutes);
    this.app.use('/api/users', userRoutes);
    this.app.use('/api/requests', requestRoutes);
    this.app.use('/api/password', passwordRoutes);

    // API info endpoint
    this.app.get('/api', (req, res) => {
      res.json({
        message: 'Auth Password Manager API',
        version: '1.0.0',
        environment: config.nodeEnv,
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: {
          code: 'NOT_FOUND',
          message: 'Route not found',
          timestamp: new Date().toISOString(),
        },
      });
    });
  }

  private initializeSocketIO(): void {
    // Initialize the socket service with authentication and room management
    this.socketService = initializeSocketService(this.io);
    
    console.log('Socket.io server initialized with authentication and room management');
  }

  public async start(): Promise<void> {
    try {
      // Connect to databases
      await DatabaseConnection.getInstance().connect();
      await RedisConnection.getInstance().connect();

      // Start notification scheduler
      notificationScheduler.start();

      // Start expiration service
      expirationService.start();

      // Start server
      this.httpServer.listen(config.port, () => {
        console.log(
          `Server running on port ${config.port} in ${config.nodeEnv} mode`
        );
        console.log(`Health check: http://localhost:${config.port}/health`);
      });
    } catch (error) {
      console.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  public async stop(): Promise<void> {
    try {
      // Stop notification scheduler
      notificationScheduler.stop();

      // Stop expiration service
      expirationService.stop();

      // Close database connections
      await DatabaseConnection.getInstance().disconnect();
      await RedisConnection.getInstance().disconnect();

      // Close server
      this.httpServer.close(() => {
        console.log('Server stopped');
      });
    } catch (error) {
      console.error('Error stopping server:', error);
    }
  }

  public getApp(): express.Application {
    return this.app;
  }

  public getIO(): SocketIOServer {
    return this.io;
  }
}

// Start server if this file is run directly
if (require.main === module) {
  const server = new Server();

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await server.stop();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    await server.stop();
    process.exit(0);
  });

  server.start().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default Server;
