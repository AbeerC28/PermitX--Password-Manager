import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

// Context Providers
import { AppProvider } from './contexts/AppContext';

// Components
import { SessionManager } from './components/auth/SessionManager';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { LoginPage } from './components/auth/LoginPage';
import { AdminLayout } from './components/layout/AdminLayout';
import { UserLayout } from './components/layout/UserLayout';

// Pages
import {
  UserRequestPage,
  UserStatusPage,
  UserAccessPage,
  AdminDashboardPage,
  AdminUsersPage,
  AdminApprovalsPage,
  AdminAuditPage,
} from './pages';

// Notification System
import { NotificationSystem } from './components/common/NotificationSystem';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
        },
      },
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AppProvider>
        <SessionManager>
          <Router>
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<Navigate to="/request" replace />} />
              
              {/* User Routes */}
              <Route path="/request" element={<UserLayout />}>
                <Route index element={<UserRequestPage />} />
              </Route>
              <Route path="/status/:requestId" element={<UserLayout />}>
                <Route index element={<UserStatusPage />} />
              </Route>
              <Route path="/access/:requestId" element={<UserLayout />}>
                <Route index element={<UserAccessPage />} />
              </Route>

              {/* Admin Authentication */}
              <Route 
                path="/admin/login" 
                element={
                  <ProtectedRoute requireAuth={false}>
                    <LoginPage />
                  </ProtectedRoute>
                } 
              />

              {/* Protected Admin Routes */}
              <Route 
                path="/admin" 
                element={
                  <ProtectedRoute>
                    <AdminLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<Navigate to="/admin/dashboard" replace />} />
                <Route path="dashboard" element={<AdminDashboardPage />} />
                <Route path="users" element={<AdminUsersPage />} />
                <Route path="approvals" element={<AdminApprovalsPage />} />
                <Route path="audit" element={<AdminAuditPage />} />
              </Route>

              {/* Catch all route */}
              <Route path="*" element={<Navigate to="/request" replace />} />
            </Routes>
            
            {/* Global Notification System */}
            <NotificationSystem />
          </Router>
        </SessionManager>
      </AppProvider>
    </ThemeProvider>
  );
}

export default App;