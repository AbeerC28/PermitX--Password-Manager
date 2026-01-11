import React, { createContext, useContext, useReducer, ReactNode } from 'react';
import { User } from '../services/userApi';
import { ApprovalRequest } from '../services/requestApi';

// State interface
export interface AppState {
  // Authentication state
  isAuthenticated: boolean;
  admin: {
    id: string;
    username: string;
    email: string;
  } | null;
  
  // Loading states
  loading: {
    auth: boolean;
    users: boolean;
    requests: boolean;
    general: boolean;
  };
  
  // Error states
  error: {
    auth: string | null;
    users: string | null;
    requests: string | null;
    general: string | null;
  };
  
  // Data
  users: User[];
  requests: ApprovalRequest[];
  currentRequest: ApprovalRequest | null;
  
  // UI state
  notifications: Array<{
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    message: string;
    timestamp: Date;
  }>;
}

// Action types
export type AppAction =
  // Authentication actions
  | { type: 'AUTH_START' }
  | { type: 'AUTH_SUCCESS'; payload: { admin: AppState['admin']; token: string } }
  | { type: 'AUTH_FAILURE'; payload: string }
  | { type: 'AUTH_LOGOUT' }
  
  // Loading actions
  | { type: 'SET_LOADING'; payload: { key: keyof AppState['loading']; value: boolean } }
  
  // Error actions
  | { type: 'SET_ERROR'; payload: { key: keyof AppState['error']; value: string | null } }
  | { type: 'CLEAR_ERRORS' }
  
  // Users actions
  | { type: 'USERS_LOAD_START' }
  | { type: 'USERS_LOAD_SUCCESS'; payload: User[] }
  | { type: 'USERS_LOAD_FAILURE'; payload: string }
  | { type: 'USER_CREATE_SUCCESS'; payload: User }
  | { type: 'USER_UPDATE_SUCCESS'; payload: User }
  | { type: 'USER_DELETE_SUCCESS'; payload: string }
  
  // Requests actions
  | { type: 'REQUESTS_LOAD_START' }
  | { type: 'REQUESTS_LOAD_SUCCESS'; payload: ApprovalRequest[] }
  | { type: 'REQUESTS_LOAD_FAILURE'; payload: string }
  | { type: 'REQUEST_CREATE_SUCCESS'; payload: ApprovalRequest }
  | { type: 'REQUEST_UPDATE_SUCCESS'; payload: ApprovalRequest }
  | { type: 'SET_CURRENT_REQUEST'; payload: ApprovalRequest | null }
  
  // Notification actions
  | { type: 'ADD_NOTIFICATION'; payload: Omit<AppState['notifications'][0], 'id' | 'timestamp'> }
  | { type: 'REMOVE_NOTIFICATION'; payload: string };

// Initial state
const initialState: AppState = {
  isAuthenticated: false,
  admin: null,
  loading: {
    auth: false,
    users: false,
    requests: false,
    general: false,
  },
  error: {
    auth: null,
    users: null,
    requests: null,
    general: null,
  },
  users: [],
  requests: [],
  currentRequest: null,
  notifications: [],
};

// Reducer
function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    // Authentication
    case 'AUTH_START':
      return {
        ...state,
        loading: { ...state.loading, auth: true },
        error: { ...state.error, auth: null },
      };
    
    case 'AUTH_SUCCESS':
      localStorage.setItem('authToken', action.payload.token);
      return {
        ...state,
        isAuthenticated: true,
        admin: action.payload.admin,
        loading: { ...state.loading, auth: false },
        error: { ...state.error, auth: null },
      };
    
    case 'AUTH_FAILURE':
      localStorage.removeItem('authToken');
      return {
        ...state,
        isAuthenticated: false,
        admin: null,
        loading: { ...state.loading, auth: false },
        error: { ...state.error, auth: action.payload },
      };
    
    case 'AUTH_LOGOUT':
      localStorage.removeItem('authToken');
      return {
        ...initialState,
      };
    
    // Loading
    case 'SET_LOADING':
      return {
        ...state,
        loading: { ...state.loading, [action.payload.key]: action.payload.value },
      };
    
    // Errors
    case 'SET_ERROR':
      return {
        ...state,
        error: { ...state.error, [action.payload.key]: action.payload.value },
      };
    
    case 'CLEAR_ERRORS':
      return {
        ...state,
        error: {
          auth: null,
          users: null,
          requests: null,
          general: null,
        },
      };
    
    // Users
    case 'USERS_LOAD_START':
      return {
        ...state,
        loading: { ...state.loading, users: true },
        error: { ...state.error, users: null },
      };
    
    case 'USERS_LOAD_SUCCESS':
      return {
        ...state,
        users: action.payload,
        loading: { ...state.loading, users: false },
      };
    
    case 'USERS_LOAD_FAILURE':
      return {
        ...state,
        loading: { ...state.loading, users: false },
        error: { ...state.error, users: action.payload },
      };
    
    case 'USER_CREATE_SUCCESS':
      return {
        ...state,
        users: [...state.users, action.payload],
      };
    
    case 'USER_UPDATE_SUCCESS':
      return {
        ...state,
        users: state.users.map(user => 
          user._id === action.payload._id ? action.payload : user
        ),
      };
    
    case 'USER_DELETE_SUCCESS':
      return {
        ...state,
        users: state.users.filter(user => user._id !== action.payload),
      };
    
    // Requests
    case 'REQUESTS_LOAD_START':
      return {
        ...state,
        loading: { ...state.loading, requests: true },
        error: { ...state.error, requests: null },
      };
    
    case 'REQUESTS_LOAD_SUCCESS':
      return {
        ...state,
        requests: action.payload,
        loading: { ...state.loading, requests: false },
      };
    
    case 'REQUESTS_LOAD_FAILURE':
      return {
        ...state,
        loading: { ...state.loading, requests: false },
        error: { ...state.error, requests: action.payload },
      };
    
    case 'REQUEST_CREATE_SUCCESS':
      return {
        ...state,
        requests: [...state.requests, action.payload],
        currentRequest: action.payload,
      };
    
    case 'REQUEST_UPDATE_SUCCESS':
      return {
        ...state,
        requests: state.requests.map(request => 
          request._id === action.payload._id ? action.payload : request
        ),
        currentRequest: state.currentRequest?._id === action.payload._id ? action.payload : state.currentRequest,
      };
    
    case 'SET_CURRENT_REQUEST':
      return {
        ...state,
        currentRequest: action.payload,
      };
    
    // Notifications
    case 'ADD_NOTIFICATION':
      const newNotification = {
        ...action.payload,
        id: Date.now().toString(),
        timestamp: new Date(),
      };
      return {
        ...state,
        notifications: [...state.notifications, newNotification],
      };
    
    case 'REMOVE_NOTIFICATION':
      return {
        ...state,
        notifications: state.notifications.filter(n => n.id !== action.payload),
      };
    
    default:
      return state;
  }
}

// Context
const AppContext = createContext<{
  state: AppState;
  dispatch: React.Dispatch<AppAction>;
} | null>(null);

// Provider component
export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialState);

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      {children}
    </AppContext.Provider>
  );
}

// Hook to use the context
export function useAppContext() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
}