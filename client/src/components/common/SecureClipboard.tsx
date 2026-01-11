import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Alert,
  Typography,
  LinearProgress,
  Chip,
  Card,
  CardContent,
  Tooltip,
  IconButton
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Timer as TimerIcon,
  Security as SecurityIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import { useClipboard, getClipboardCapabilities } from '../../utils/clipboard';

interface SecureClipboardProps {
  maskedPassword: string;
  onCopy?: (success: boolean, message: string) => void;
  clearAfter?: number; // Time in milliseconds
  disabled?: boolean;
  variant?: 'button' | 'card';
  showTimer?: boolean;
}

export const SecureClipboard: React.FC<SecureClipboardProps> = ({
  maskedPassword,
  onCopy,
  clearAfter = 60000, // 60 seconds default as per requirement 4.3
  disabled = false,
  variant = 'button',
  showTimer = true
}) => {
  const { isSupported, copyPassword } = useClipboard();
  const [copying, setCopying] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const [capabilities] = useState(() => getClipboardCapabilities());

  useEffect(() => {
    if (copied && clearAfter > 0 && showTimer) {
      setTimeRemaining(clearAfter);
      
      const interval = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev === null || prev <= 1000) {
            clearInterval(interval);
            setCopied(false);
            return null;
          }
          return prev - 1000;
        });
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [copied, clearAfter, showTimer]);

  const handleCopy = async () => {
    if (!isSupported || disabled) return;

    setCopying(true);
    try {
      const result = await copyPassword(maskedPassword, { clearAfter });
      setCopied(result.success);
      onCopy?.(result.success, result.message);
    } catch (error) {
      const message = 'Failed to copy password to clipboard';
      onCopy?.(false, message);
    } finally {
      setCopying(false);
    }
  };

  const formatTimeRemaining = (ms: number): string => {
    const seconds = Math.ceil(ms / 1000);
    return `${seconds}s`;
  };

  if (!isSupported) {
    return (
      <Alert severity="warning" icon={<WarningIcon />}>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="body2">
            Clipboard functionality is not supported in your browser. 
            Please manually copy the password when it's displayed.
          </Typography>
          <Tooltip title={`Browser: ${capabilities.userAgent.split(' ')[0]} | Secure Context: ${capabilities.secureContext ? 'Yes' : 'No'}`}>
            <IconButton size="small">
              <InfoIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Alert>
    );
  }

  if (variant === 'card') {
    return (
      <Card variant="outlined">
        <CardContent>
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">
              Secure Password Access
            </Typography>
          </Box>

          <Alert severity="info" sx={{ mb: 2 }}>
            <Box display="flex" alignItems="center" justifyContent="space-between">
              <Typography variant="body2">
                Your password will be copied to the clipboard in a secure format. 
                It will be automatically cleared after {Math.round(clearAfter / 1000)} seconds.
              </Typography>
              <Tooltip title={`Method: ${capabilities.method} | Features: ${capabilities.features.join(', ')}`}>
                <IconButton size="small">
                  <InfoIcon />
                </IconButton>
              </Tooltip>
            </Box>
          </Alert>

          <Button
            fullWidth
            variant="contained"
            size="large"
            onClick={handleCopy}
            disabled={disabled || copying}
            startIcon={copying ? undefined : copied ? <CheckIcon /> : <CopyIcon />}
            color={copied ? 'success' : 'primary'}
            sx={{ mb: 2 }}
          >
            {copying ? (
              <Box display="flex" alignItems="center" gap={1}>
                <LinearProgress sx={{ width: 100, height: 4 }} />
                <Typography>Copying...</Typography>
              </Box>
            ) : copied ? (
              'Password Copied!'
            ) : (
              'Copy Password to Clipboard'
            )}
          </Button>

          {copied && timeRemaining !== null && showTimer && (
            <Box display="flex" alignItems="center" justifyContent="center" gap={1}>
              <TimerIcon color="warning" fontSize="small" />
              <Typography variant="body2" color="warning.main">
                Clipboard will be cleared in {formatTimeRemaining(timeRemaining)}
              </Typography>
            </Box>
          )}

          {copied && (
            <Alert severity="success" sx={{ mt: 2 }}>
              Password successfully copied to clipboard!
            </Alert>
          )}
        </CardContent>
      </Card>
    );
  }

  return (
    <Box>
      <Button
        variant="contained"
        onClick={handleCopy}
        disabled={disabled || copying}
        startIcon={copying ? undefined : copied ? <CheckIcon /> : <CopyIcon />}
        color={copied ? 'success' : 'primary'}
        sx={{ mb: 1 }}
      >
        {copying ? 'Copying...' : copied ? 'Copied!' : 'Copy Password'}
      </Button>

      {copied && timeRemaining !== null && showTimer && (
        <Box display="flex" alignItems="center" gap={1} mt={1}>
          <Chip
            icon={<TimerIcon />}
            label={`Clears in ${formatTimeRemaining(timeRemaining)}`}
            color="warning"
            size="small"
            variant="outlined"
          />
        </Box>
      )}
    </Box>
  );
};