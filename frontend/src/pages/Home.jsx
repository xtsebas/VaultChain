import { Box, Container, Paper, Typography } from '@mui/material';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import SessionWidget from '../components/SessionWidget';
import { getSessionUser } from '../services/authService';

export default function Home() {
  const user = getSessionUser();

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        background: 'linear-gradient(135deg, #1a237e 0%, #283593 50%, #3949ab 100%)',
      }}
    >
      <Container maxWidth="sm">
        <Paper elevation={6} sx={{ p: 5, borderRadius: 3, textAlign: 'center' }}>
          <Box
            sx={{
              bgcolor: 'primary.main',
              borderRadius: '50%',
              p: 1.5,
              mb: 2,
              display: 'inline-flex',
            }}
          >
            <LockOutlinedIcon sx={{ color: 'white', fontSize: 36 }} />
          </Box>
          <Typography variant="h5" fontWeight={700} color="primary.dark" gutterBottom>
            Bienvenido, {user?.display_name}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Tu sesión está activa. Usa el icono en la esquina inferior derecha para ver los datos de tu sesión.
          </Typography>
        </Paper>
      </Container>

      <SessionWidget />
    </Box>
  );
}
