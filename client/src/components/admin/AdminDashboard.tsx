import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Alert,
  CircularProgress,
  Button,
  Badge
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  HourglassEmpty as PendingIcon,
  CheckCircle as ApprovedIcon,
  Cancel as DeniedIcon,
  AccessTime as ExpiredIcon,
  Person as PersonIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';

export interface DashboardStats {
  totalUsers: number;
  pendingRequests: number;
  approvedToday: number;
  deniedToday: number;
  expiredToday: number;
}

export interface RecentRequest {
  _id: string;
  userEmail: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  requestedAt: Date;
  respondedAt?: Date;
  timeAgo: string;
}

interface AdminDashboardProps {
  stats: DashboardStats;
  recentRequests: RecentRequest[];
  isLoading?: boolean;
  error?: string;
  onRefresh?: () => void;
  onViewAllRequests?: () => void;
  onViewRequest?: (requestId: string) => void;
}

export const AdminDashboard: React.FC<AdminDashboardProps> = ({
  stats,
  recentRequests,
  isLoading = false,
  error,
  onRefresh,
  onViewAllRequests,
  onViewRequest
}) => {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  useEffect(() => {
    setLastUpdated(new Date());
  }, [stats, recentRequests]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <PendingIcon color="warning" />;
      case 'approved':
        return <ApprovedIcon color="success" />;
      case 'denied':
        return <DeniedIcon color="error" />;
      case 'expired':
        return <ExpiredIcon color="disabled" />;
      default:
        return <PendingIcon />;
    }
  };

  const getStatusColor = (status: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (status) {
      case 'pending':
        return 'warning';
      case 'approved':
        return 'success';
      case 'denied':
        return 'error';
      case 'expired':
        return 'default';
      default:
        return 'default';
    }
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={60} />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <DashboardIcon color="primary" fontSize="large" />
          <Typography variant="h4" component="h1">
            Admin Dashboard
          </Typography>
        </Box>
        
        <Box display="flex" alignItems="center" gap={2}>
          <Typography variant="caption" color="text.secondary">
            Last updated: {lastUpdated.toLocaleTimeString()}
          </Typography>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={onRefresh}
            disabled={isLoading}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <PersonIcon color="primary" fontSize="large" />
                <Box>
                  <Typography variant="h4" component="div">
                    {stats.totalUsers}
                  </Typography>
                  <Typography color="text.secondary">
                    Total Users
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <Badge badgeContent={stats.pendingRequests} color="warning">
                  <PendingIcon color="warning" fontSize="large" />
                </Badge>
                <Box>
                  <Typography variant="h4" component="div">
                    {stats.pendingRequests}
                  </Typography>
                  <Typography color="text.secondary">
                    Pending Requests
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <ApprovedIcon color="success" fontSize="large" />
                <Box>
                  <Typography variant="h4" component="div">
                    {stats.approvedToday}
                  </Typography>
                  <Typography color="text.secondary">
                    Approved Today
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2}>
                <DeniedIcon color="error" fontSize="large" />
                <Box>
                  <Typography variant="h4" component="div">
                    {stats.deniedToday}
                  </Typography>
                  <Typography color="text.secondary">
                    Denied Today
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Requests */}
      <Paper elevation={3} sx={{ p: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6" component="h2">
            Recent Requests
          </Typography>
          <Button
            variant="text"
            onClick={onViewAllRequests}
            disabled={!onViewAllRequests}
          >
            View All
          </Button>
        </Box>

        {recentRequests.length === 0 ? (
          <Alert severity="info">
            No recent requests found.
          </Alert>
        ) : (
          <List>
            {recentRequests.map((request, index) => (
              <React.Fragment key={request._id}>
                <ListItem
                  {...(onViewRequest && { 
                    component: 'div',
                    onClick: () => onViewRequest(request._id),
                    sx: {
                      borderRadius: 1,
                      cursor: 'pointer',
                      '&:hover': {
                        backgroundColor: 'action.hover'
                      }
                    }
                  })}
                >
                  <ListItemIcon>
                    {getStatusIcon(request.status)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={2}>
                        <Typography variant="body1">
                          {request.userEmail}
                        </Typography>
                        <Chip
                          label={request.status.toUpperCase()}
                          color={getStatusColor(request.status)}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          Requested {request.timeAgo}
                        </Typography>
                        {request.respondedAt && (
                          <Typography variant="body2" color="text.secondary">
                            Responded {new Date(request.respondedAt).toLocaleString()}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                </ListItem>
                {index < recentRequests.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        )}
      </Paper>

      {/* Quick Actions */}
      {stats.pendingRequests > 0 && (
        <Alert severity="warning" sx={{ mt: 3 }}>
          <Typography variant="body1">
            You have {stats.pendingRequests} pending request{stats.pendingRequests !== 1 ? 's' : ''} 
            that need{stats.pendingRequests === 1 ? 's' : ''} your attention.
          </Typography>
          <Button
            variant="contained"
            color="warning"
            onClick={onViewAllRequests}
            sx={{ mt: 1 }}
            disabled={!onViewAllRequests}
          >
            Review Pending Requests
          </Button>
        </Alert>
      )}
    </Box>
  );
};