# Auth Password Manager

A centralized credential management system where administrators control access to user passwords through an approval-based workflow.

## Features

- **Admin-controlled password access**: Single administrator manages all credentials
- **Approval workflow**: Users request access, admin approves/denies
- **Secure password delivery**: Masked passwords via clipboard without viewing actual text
- **Real-time notifications**: WebSocket-based status updates
- **Comprehensive audit logging**: Track all system activities
- **Multi-channel notifications**: Email and SMS support

## Technology Stack

### Backend
- **Node.js** with **Express.js** and **TypeScript**
- **MongoDB** with **Mongoose** ODM
- **Redis** for caching and session management
- **Socket.io** for real-time communication
- **Argon2** for password hashing
- **JWT** for authentication

### Frontend
- **React 18** with **TypeScript**
- **Material-UI** for components
- **Vite** for development and building
- **Socket.io-client** for real-time updates

## Prerequisites

- Node.js (v18 or higher)
- MongoDB (v5 or higher)
- Redis (v6 or higher)
- npm or yarn

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth-password-manager
   ```

2. **Install backend dependencies**
   ```bash
   npm install
   ```

3. **Install frontend dependencies**
   ```bash
   cd client
   npm install
   cd ..
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration values.

5. **Start MongoDB and Redis**
   Make sure MongoDB and Redis are running on your system.

## Development

### Start the development environment
```bash
npm run dev
```

This will start:
- Backend server on `http://localhost:5000`
- Frontend development server on `http://localhost:3000`

### Available Scripts

#### Backend
- `npm run server:dev` - Start backend in development mode
- `npm run build:server` - Build backend for production
- `npm run test` - Run backend tests
- `npm run lint` - Lint backend code
- `npm run format` - Format backend code

#### Frontend
- `npm run client:dev` - Start frontend in development mode
- `npm run build:client` - Build frontend for production

#### Full Stack
- `npm run dev` - Start both backend and frontend
- `npm run build` - Build both backend and frontend
- `npm start` - Start production server

## Environment Variables

Copy `.env.example` to `.env` and configure the following:

### Required Variables
- `JWT_SECRET` - Secret key for JWT tokens
- `ENCRYPTION_KEY` - Key for password encryption (32 characters)
- `MONGODB_URI` - MongoDB connection string

### Optional Variables
- `PORT` - Server port (default: 5000)
- `REDIS_HOST` - Redis host (default: localhost)
- `REDIS_PORT` - Redis port (default: 6379)
- `SENDGRID_API_KEY` - SendGrid API key for email notifications
- `TWILIO_ACCOUNT_SID` - Twilio account SID for SMS notifications
- `TWILIO_AUTH_TOKEN` - Twilio auth token

## API Endpoints

### Health Check
- `GET /health` - Server health status

### API Root
- `GET /api` - API information

## Testing

Run the test suite:
```bash
npm test
```

## Project Structure

```
auth-password-manager/
├── src/                    # Backend source code
│   ├── config/            # Configuration files
│   ├── controllers/       # Route controllers
│   ├── middleware/        # Express middleware
│   ├── models/           # Database models
│   ├── services/         # Business logic services
│   ├── utils/            # Utility functions
│   ├── test/             # Test setup
│   └── server.ts         # Main server file
├── client/               # Frontend React application
│   ├── src/             # React source code
│   ├── public/          # Static assets
│   └── package.json     # Frontend dependencies
├── dist/                # Built backend code
├── .env                 # Environment variables
└── package.json         # Backend dependencies
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details