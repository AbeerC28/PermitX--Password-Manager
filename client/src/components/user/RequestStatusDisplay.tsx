import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  LinearProgress,
  Alert,
  Card,
  CardContent,
  Divider
} from '@mui/material';
import {
  HourglassEmpty as PendingIcon,
  CheckCircle as ApprovedIcon,
  Cancel as DeniedIcon,
  AccessTime as ExpiredIcon
} from '@mui/icons-material';

export interface RequestStatus {
  _id: string;
  userEmail: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  requestedAt: Date;
  respondedAt?: Date;
  expiresAt: Date;
  adminResponse?: {
    reason?: string;
    respondedAt: Date;
  };
}

interface RequestStatusDisplayProps {
  request: RequestStatus | null;
  isLoading?: boolean;
  onStatusUpdate?: (status: RequestStatus) => void;
}

export const RequestStatusDisplay: React.FC<RequestStatusDisplayProps> = ({
  request,
  isLoading = false,
  onStatusUpdate
}) => {
  const [timeRemaining, setTimeRemaining] = useState<string>('');

  useEffect(() => {
    if (!request || request.status !== 'pending') return;

    const updateTimeRemaining = () => {
      const now = new Date();
      const expiresAt = new Date(request.expiresAt);
      const diff = expiresAt.getTime() - now.getTime();

      if (diff <= 0) {
        setTimeRemaining('Expired');
        // Notify parent of expiration
        if (onStatusUpdate) {
          onStatusUpdate({ ...request, status: 'expired' });
        }
        return;
      }

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setTimeRemaining(`${hours}h ${minutes}m ${seconds}s`);
    };

    updateTimeRemaining();
    const interval = setInterval(updateTimeRemaining, 1000);

    return () => clearInterval(interval);
  }, [request, onStatusUpdate]);

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

  const formatDate = (date: Date | string) => {
    return new Date(date).toLocaleString();
  };

  if (isLoading) {
    return (
      <Paper elevation={3} sx={{ p: 4, maxWidth: 500, mx: 'auto' }}>
        <Typography variant="h6" gutterBottom>
          Checking Request Status...
        </Typography>
        <LinearProgress />
      </Paper>
    );
  }

  if (!request) {
    return (
      <Alert severity="info" sx={{ maxWidth: 500, mx: 'auto' }}>
        No active password request found. Submit a request to get started.
      </Alert>
    );
  }

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 500, mx: 'auto' }}>
      <Box display="flex" alignItems="center" gap={2} mb={3}>
        {getStatusIcon(request.status)}
        <Typography variant="h6">
          Request Status
        </Typography>
        <Chip
          label={request.status.toUpperCase()}
          color={getStatusColor(request.status)}
          variant="filled"
        />
      </Box>

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Email
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            {request.userEmail}
          </Typography>

          <Typography variant="body2" color="text.secondary" gutterBottom>
            Requested At
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            {formatDate(request.requestedAt)}
          </Typography>

          {request.status === 'pending' && (
            <>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Time Remaining
              </Typography>
              <Typography variant="body1" color="warning.main" sx={{ mb: 2 }}>
                {timeRemaining}
              </Typography>
            </>
          )}

          {request.respondedAt && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Admin Response
              </Typography>
              <Typography variant="body1" sx={{ mb: 1 }}>
                {formatDate(request.respondedAt)}
              </Typography>
              
              {request.adminResponse?.reason && (
                <>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Reason
                  </Typography>
                  <Typography variant="body1">
                    {request.adminResponse.reason}
                  </Typography>
                </>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {request.status === 'pending' && (
        <Alert severity="info">
          Your request is pending admin approval. You will be notified when a decision is made.
        </Alert>
      )}

      {request.status === 'approved' && (
        <Alert severity="success">
          Your request has been approved! You can now access your password.
        </Alert>
      )}

      {request.status === 'denied' && (
        <Alert severity="error">
          Your request has been denied. Please contact your administrator for more information.
        </Alert>
      )}

      {request.status === 'expired' && (
        <Alert severity="warning">
          Your request has expired. Please submit a new request if you still need access.
        </Alert>
      )}
    </Paper>
  );
};