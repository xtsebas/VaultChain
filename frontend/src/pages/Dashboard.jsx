import { useState } from 'react';
import { alpha } from '@mui/material/styles';
import {
  AppBar,
  Avatar,
  Box,
  Card,
  CardContent,
  Grid,
  IconButton,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import KeyIcon from '@mui/icons-material/Key';
import HistoryIcon from '@mui/icons-material/History';
import LinkIcon from '@mui/icons-material/Link';
import SessionWidget from '../components/SessionWidget';
import { getSessionUser } from '../services/authService';

function getInitials(name = '') {
  return name
    .split(' ')
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase())
    .join('');
}

const modules = [
  {
    icon: <LockIcon sx={{ fontSize: 36, color: 'primary.main' }} />,
    title: '1',
    description: '',
  },
  {
    icon: <KeyIcon sx={{ fontSize: 36, color: 'secondary.main' }} />,
    title: '2',
    description: '',
  },
  {
    icon: <HistoryIcon sx={{ fontSize: 36, color: 'success.main' }} />,
    title: '3',
    description: '',
  },
  {
    icon: <LinkIcon sx={{ fontSize: 36, color: 'warning.main' }} />,
    title: '4',
    description: '',
  },
];

export default function Dashboard() {
  const user = getSessionUser();
  const [profileAnchor, setProfileAnchor] = useState(null);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', bgcolor: 'grey.100' }}>
      {/* AppBar */}
      <AppBar position="fixed" elevation={2}>
        <Toolbar>
          <LockIcon sx={{ mr: 1.5 }} />
          <Typography variant="h6" fontWeight={700} sx={{ flexGrow: 1 }}>
            VaultChain
          </Typography>
          <Tooltip title="Mi perfil">
            <IconButton onClick={(e) => setProfileAnchor(e.currentTarget)} sx={{ p: 0 }}>
              <Avatar
                sx={{
                  width: 38,
                  height: 38,
                  bgcolor: 'primary.dark',
                  border: (t) => `2px solid ${alpha(t.palette.primary.contrastText, 0.6)}`,
                }}
              >
                {getInitials(user?.display_name)}
              </Avatar>
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      {/* Session popover controlled from AppBar avatar */}
      <SessionWidget
        anchorEl={profileAnchor}
        onClose={() => setProfileAnchor(null)}
      />

      {/* Content */}
      <Box component="main" sx={{ flexGrow: 1, mt: 8, px: { xs: 2, sm: 4 }, py: 4 }}>
        {/* Welcome */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h5" fontWeight={700} color="text.primary">
            Hola, {user?.display_name}
          </Typography>
          <Typography variant="body2" color="text.secondary" mt={0.5}>
            Bienvenido a VaultChain
          </Typography>
        </Box>

        {/* Module cards */}

      </Box>
    </Box>
  );
}
