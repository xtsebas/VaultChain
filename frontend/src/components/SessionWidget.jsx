import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { alpha } from '@mui/material/styles';
import {
  Avatar,
  Box,
  Divider,
  IconButton,
  Popover,
  Tooltip,
  Typography,
} from '@mui/material';
import LogoutIcon from '@mui/icons-material/Logout';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import EmailIcon from '@mui/icons-material/Email';
import BadgeIcon from '@mui/icons-material/Badge';
import { clearTokens, getSessionUser, getExpiresAt } from '../services/authService';

function getInitials(name = '') {
  return name
    .split(' ')
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase())
    .join('');
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return '—';
  const diff = expiresAt - Date.now();
  if (diff <= 0) return 'Expirado';
  const mins = Math.floor(diff / 60000);
  const secs = Math.floor((diff % 60000) / 1000);
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export default function SessionWidget({ anchorEl: externalAnchor, onClose: externalClose }) {
  const navigate = useNavigate();
  const user = getSessionUser();
  const expiresAt = getExpiresAt();
  const [anchor, setAnchor] = useState(null);
  const [, setTick] = useState(0);
  const intervalRef = useRef(null);

  if (!user) return null;

  const controlled = externalAnchor !== undefined;
  const open = controlled ? Boolean(externalAnchor) : Boolean(anchor);
  const anchorEl = controlled ? externalAnchor : anchor;

  function handleOpen(e) {
    setAnchor(e.currentTarget);
    intervalRef.current = setInterval(() => setTick((t) => t + 1), 1000);
  }

  function handleClose() {
    clearInterval(intervalRef.current);
    intervalRef.current = null;
    setAnchor(null);
    externalClose?.();
  }

  function handleLogout() {
    handleClose();
    clearTokens();
    navigate('/login');
  }

  const nearExpiry = expiresAt - Date.now() < 120_000;

  return (
    <>
      {!controlled && (
        <Tooltip title="Mi perfil" placement="left">
          <IconButton
            onClick={handleOpen}
            sx={{
              position: 'fixed',
              top: 12,
              right: 16,
              p: 0,
              '&:hover': { transform: 'scale(1.08)' },
              transition: 'transform 0.15s',
            }}
          >
            <Avatar
              sx={{
                width: 40,
                height: 40,
                bgcolor: 'primary.main',
                border: (t) => `2px solid ${t.palette.common.white}`,
              }}
            >
              {getInitials(user.display_name)}
            </Avatar>
          </IconButton>
        </Tooltip>
      )}

      <Popover
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{
          paper: {
            elevation: 8,
            sx: { borderRadius: 2, width: 280, overflow: 'hidden', mt: 1 },
          },
        }}
      >
        {/* Header */}
        <Box
          sx={{
            bgcolor: 'surface.main',
            px: 2,
            py: 2,
            display: 'flex',
            alignItems: 'center',
            gap: 1.5,
          }}
        >
          <Avatar sx={{ width: 42, height: 42, bgcolor: 'surface.light' }}>
            {getInitials(user.display_name)}
          </Avatar>
          <Typography variant="subtitle1" fontWeight={700} noWrap sx={{ color: 'surface.contrastText' }}>
            {user.display_name}
          </Typography>
        </Box>

        {/* Details */}
        <Box sx={{ px: 2, py: 1.5, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
            <EmailIcon fontSize="small" color="action" sx={{ mt: 0.2 }} />
            <Box>
              <Typography variant="caption" color="text.secondary">Correo</Typography>
              <Typography variant="body2" fontWeight={500}>{user.email}</Typography>
            </Box>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
            <BadgeIcon fontSize="small" color="action" sx={{ mt: 0.2 }} />
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="caption" color="text.secondary">ID de usuario</Typography>
              <Typography variant="caption" display="block" fontWeight={500} sx={{ wordBreak: 'break-all' }}>
                {user.id}
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
            <AccessTimeIcon fontSize="small" color="action" sx={{ mt: 0.2 }} />
            <Box>
              <Typography variant="caption" color="text.secondary">Token expira en</Typography>
              <Typography
                variant="body2"
                fontWeight={600}
                color={nearExpiry ? 'error.main' : 'success.main'}
              >
                {formatExpiry(expiresAt)}
              </Typography>
            </Box>
          </Box>
        </Box>

        <Divider />

        <Box
          onClick={handleLogout}
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1.5,
            px: 2,
            py: 1.5,
            cursor: 'pointer',
            color: 'error.main',
            '&:hover': { bgcolor: (t) => alpha(t.palette.error.main, 0.08) },
            transition: 'background 0.15s',
          }}
        >
          <LogoutIcon fontSize="small" />
          <Typography variant="body2" fontWeight={600}>Cerrar sesión</Typography>
        </Box>
      </Popover>
    </>
  );
}
