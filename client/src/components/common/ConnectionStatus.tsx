import React from 'react';
import { Box, Chip, Tooltip } from '@mui/material';
import { 
  Wifi as ConnectedIcon, 
  WifiOff as DisconnectedIcon,
  Sync as ConnectingIcon,
  Error as ErrorIcon 
} from '@mui/icons-material';
import { useSocket } from '../../hooks/useSocket';

export function ConnectionStatus() {
  const { connectionStatus } = useSocket();

  const getStatusConfig = () => {
    switch (connectionStatus) {
      case 'connected':
        return {
          label: 'Connected',
          color: 'success' as const,
          icon: <ConnectedIcon fontSize="small" />,
          tooltip: 'Real-time connection active',
        };
      case 'connecting':
        return {
          label: 'Connecting',
          color: 'warning' as const,
          icon: <ConnectingIcon fontSize="small" />,
          tooltip: 'Establishing real-time connection...',
        };
      case 'error':
        return {
          label: 'Error',
          color: 'error' as const,
          icon: <ErrorIcon fontSize="small" />,
          tooltip: 'Connection error - some features may not work',
        };
      case 'disconnected':
      default:
        return {
          label: 'Disconnected',
          color: 'default' as const,
          icon: <DisconnectedIcon fontSize="small" />,
          tooltip: 'Real-time connection not active',
        };
    }
  };

  const config = getStatusConfig();

  return (
    <Box sx={{ display: 'flex', alignItems: 'center' }}>
      <Tooltip title={config.tooltip} arrow>
        <Chip
          icon={config.icon}
          label={config.label}
          color={config.color}
          size="small"
          variant="outlined"
          sx={{ 
            fontSize: '0.75rem',
            height: 24,
          }}
        />
      </Tooltip>
    </Box>
  );
}