import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Badge
} from '@mui/material';
import {
  CheckCircle as ApproveIcon,
  Cancel as DenyIcon,
  HourglassEmpty as PendingIcon,
  Person as PersonIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';

export interface ApprovalRequest {
  _id: string;
  userId: string;
  userEmail: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  requestedAt: Date;
  respondedAt?: Date;
  expiresAt: Date;
  adminResponse?: {
    reason?: string;
    respondedAt: Date;
  };
  timeRemaining?: string;
}

interface ApprovalPanelProps {
  requests: ApprovalRequest[];
  isLoading?: boolean;
  error?: string;
  onApprove: (requestId: string, reason?: string) => Promise<void>;
  onDeny: (requestId: string, reason: string) => Promise<void>;
  onRefresh?: () => void;
}

export const ApprovalPanel: React.FC<ApprovalPanelProps> = ({
  requests,
  isLoading = false,
  error,
  onApprove,
  onDeny,
  onRefresh
}) => {
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [denyDialogOpen, setDenyDialogOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const pendingRequests = requests.filter(req => req.status === 'pending');
  const completedRequests = requests.filter(req => req.status !== 'pending');

  const handleApprove = async () => {
    if (!selectedRequest) return;

    setSubmitting(true);
    try {
      await onApprove(selectedRequest._id, reason || undefined);
      setApproveDialogOpen(false);
      setSelectedRequest(null);
      setReason('');
    } catch (err) {
      // Error handling is managed by parent component
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeny = async () => {
    if (!selectedRequest || !reason.trim()) return;

    setSubmitting(true);
    try {
      await onDeny(selectedRequest._id, reason);
      setDenyDialogOpen(false);
      setSelectedRequest(null);
      setReason('');
    } catch (err) {
      // Error handling is managed by parent component
    } finally {
      setSubmitting(false);
    }
  };

  const openApproveDialog = (request: ApprovalRequest) => {
    setSelectedRequest(request);
    setReason('');
    setApproveDialogOpen(true);
  };

  const openDenyDialog = (request: ApprovalRequest) => {
    setSelectedRequest(request);
    setReason('');
    setDenyDialogOpen(true);
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

  const formatTimeRemaining = (expiresAt: Date) => {
    const now = new Date();
    const expires = new Date(expiresAt);
    const diff = expires.getTime() - now.getTime();

    if (diff <= 0) return 'Expired';

    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    return `${hours}h ${minutes}m`;
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <Badge badgeContent={pendingRequests.length} color="warning">
            <PendingIcon color="primary" fontSize="large" />
          </Badge>
          <Typography variant="h4" component="h1">
            Approval Panel
          </Typography>
        </Box>
        
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={onRefresh}
          disabled={isLoading}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Pending Requests */}
      <Paper elevation={3} sx={{ mb: 4 }}>
        <Box sx={{ p: 3, borderBottom: '1px solid', borderColor: 'divider' }}>
          <Typography variant="h6" component="h2">
            Pending Requests ({pendingRequests.length})
          </Typography>
        </Box>

        {isLoading ? (
          <Box display="flex" justifyContent="center" alignItems="center" sx={{ py: 4 }}>
            <CircularProgress />
          </Box>
        ) : pendingRequests.length === 0 ? (
          <Box sx={{ p: 3 }}>
            <Alert severity="info">
              No pending requests at this time.
            </Alert>
          </Box>
        ) : (
          <Box sx={{ p: 2 }}>
            {pendingRequests.map((request) => (
              <Card key={request._id} variant="outlined" sx={{ mb: 2 }}>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                    <Box flex={1}>
                      <Box display="flex" alignItems="center" gap={2} mb={2}>
                        <PersonIcon color="primary" />
                        <Typography variant="h6">
                          {request.userEmail}
                        </Typography>
                        <Chip
                          label="PENDING"
                          color="warning"
                          size="small"
                        />
                      </Box>

                      <Box display="flex" gap={4} mb={2}>
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            Requested
                          </Typography>
                          <Typography variant="body1">
                            {formatDate(request.requestedAt)}
                          </Typography>
                        </Box>
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            Expires In
                          </Typography>
                          <Typography variant="body1" color="warning.main">
                            {formatTimeRemaining(request.expiresAt)}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>

                    <Box display="flex" gap={1}>
                      <Button
                        variant="contained"
                        color="success"
                        startIcon={<ApproveIcon />}
                        onClick={() => openApproveDialog(request)}
                        size="small"
                      >
                        Approve
                      </Button>
                      <Button
                        variant="contained"
                        color="error"
                        startIcon={<DenyIcon />}
                        onClick={() => openDenyDialog(request)}
                        size="small"
                      >
                        Deny
                      </Button>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            ))}
          </Box>
        )}
      </Paper>

      {/* Recent Completed Requests */}
      <Paper elevation={3}>
        <Box sx={{ p: 3, borderBottom: '1px solid', borderColor: 'divider' }}>
          <Typography variant="h6" component="h2">
            Recent Completed Requests
          </Typography>
        </Box>

        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>User Email</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Requested</TableCell>
                <TableCell>Responded</TableCell>
                <TableCell>Reason</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {completedRequests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      No completed requests found.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                completedRequests.slice(0, 10).map((request) => (
                  <TableRow key={request._id} hover>
                    <TableCell>{request.userEmail}</TableCell>
                    <TableCell>
                      <Chip
                        label={request.status.toUpperCase()}
                        color={getStatusColor(request.status)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{formatDate(request.requestedAt)}</TableCell>
                    <TableCell>
                      {request.respondedAt ? formatDate(request.respondedAt) : '-'}
                    </TableCell>
                    <TableCell>
                      {request.adminResponse?.reason || '-'}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Approve Dialog */}
      <Dialog open={approveDialogOpen} onClose={() => setApproveDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Approve Password Request</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            You are about to approve the password request for <strong>{selectedRequest?.userEmail}</strong>.
            The user will be able to access their password once approved.
          </Alert>
          
          <TextField
            fullWidth
            label="Approval Reason (Optional)"
            multiline
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Enter a reason for approval (optional)"
            margin="normal"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApproveDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleApprove}
            variant="contained"
            color="success"
            disabled={submitting}
            startIcon={submitting ? <CircularProgress size={20} /> : <ApproveIcon />}
          >
            {submitting ? 'Approving...' : 'Approve Request'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Deny Dialog */}
      <Dialog open={denyDialogOpen} onClose={() => setDenyDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Deny Password Request</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            You are about to deny the password request for <strong>{selectedRequest?.userEmail}</strong>.
            Please provide a reason for the denial.
          </Alert>
          
          <TextField
            fullWidth
            label="Denial Reason *"
            multiline
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Enter a reason for denial (required)"
            margin="normal"
            required
            error={!reason.trim()}
            helperText={!reason.trim() ? 'Reason is required for denial' : ''}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDenyDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleDeny}
            variant="contained"
            color="error"
            disabled={submitting || !reason.trim()}
            startIcon={submitting ? <CircularProgress size={20} /> : <DenyIcon />}
          >
            {submitting ? 'Denying...' : 'Deny Request'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};