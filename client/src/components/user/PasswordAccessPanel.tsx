import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Chip,
  Card,
  CardContent
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  CheckCircle as CheckIcon,
  Timer as TimerIcon
} from '@mui/icons-material';
import { clipboardService } from '../../services/clipboardService';

interface PasswordAccessPanelProps {
  requestId: string;
  sessionToken?: string;
  isLoading?: boolean;
  error?: string;
  sessionExpiresAt?: Date;
  onCopySuccess?: (message: string) => void;
  onCopyError?: (error: string) => void;
}

export const PasswordAccessPanel: React.FC<PasswordAccessPanelProps> = ({
  requestId,
  sessionToken,
  isLoading = false,
  error,
  sessionExpiresAt,
  onCopySuccess,
  onCopyError
}) => {
  const [copied, setCopied] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState<string>('');
  const [sessionExpired, setSessionExpired] = useState(false);
  const [copying, setCopying] = useState(false);

  useEffect(() => {
    if (!sessionExpiresAt) return;

    const updateTimeRemaining = () => {
      const now = new Date();
      const expiresAt = new Date(sessionExpiresAt);
      const diff = expiresAt.getTime() - now.getTime();

      if (diff <= 0) {
        setTimeRemaining('Session Expired');
        setSessionExpired(true);
        return;
      }

      const minutes = Math.floor(diff / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setTimeRemaining(`${minutes}m ${seconds}s`);
    };

    updateTimeRemaining();
    const interval = setInterval(updateTimeRemaining, 1000);

    return () => clearInterval(interval);
  }, [sessionExpiresAt]);

  useEffect(() => {
    if (copied) {
      const timer = setTimeout(() => {
        setCopied(false);
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [copied]);

  const handleCopyPassword = async () => {
    setCopying(true);
    try {
      const result = await clipboardService.copyPasswordFromAPI(requestId, sessionToken);
      
      if (result.success) {
        setCopied(true);
        onCopySuccess?.(result.message);
      } else {
        onCopyError?.(result.message);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to copy password';
      onCopyError?.(errorMessage);
    } finally {
      setCopying(false);
    }
  };

  if (sessionExpired) {
    return (
      <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto' }}>
        <Alert severity="error">
          Your password access session has expired. Please submit a new request.
        </Alert>
      </Paper>
    );
  }

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto' }}>
      <Typography variant="h5" component="h2" gutterBottom align="center">
        Password Access
      </Typography>

      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }} align="center">
        Your password request has been approved. Click the button below to copy your password to the clipboard.
      </Typography>

      {sessionExpiresAt && (
        <Card variant="outlined" sx={{ mb: 3 }}>
          <CardContent sx={{ py: 2 }}>
            <Box display="flex" alignItems="center" gap={1}>
              <TimerIcon color="warning" fontSize="small" />
              <Typography variant="body2" color="text.secondary">
                Session expires in:
              </Typography>
              <Chip
                label={timeRemaining}
                color="warning"
                size="small"
                variant="outlined"
              />
            </Box>
          </CardContent>
        </Card>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          <strong>Security Notice:</strong> Your password will be copied to the clipboard in a masked format. 
          The clipboard will be automatically cleared after 60 seconds for security.
        </Typography>
      </Alert>

      <Button
        fullWidth
        variant="contained"
        size="large"
        onClick={handleCopyPassword}
        disabled={isLoading || sessionExpired || copying}
        startIcon={
          copying ? (
            <CircularProgress size={20} />
          ) : copied ? (
            <CheckIcon />
          ) : (
            <CopyIcon />
          )
        }
        color={copied ? 'success' : 'primary'}
        sx={{ mb: 2 }}
      >
        {copying
          ? 'Copying Password...'
          : isLoading
          ? 'Loading...'
          : copied
          ? 'Password Copied!'
          : 'Copy Password to Clipboard'
        }
      </Button>

      {copied && (
        <Alert severity="success">
          Password copied to clipboard! It will be automatically cleared in 60 seconds.
        </Alert>
      )}

      <Typography variant="caption" color="text.secondary" align="center" display="block">
        Your password is never displayed on screen for security purposes.
      </Typography>
    </Paper>
  );
};