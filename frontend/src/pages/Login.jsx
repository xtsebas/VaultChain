import { useState } from 'react';
import { useNavigate, Link as RouterLink, useLocation } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Container,
  IconButton,
  InputAdornment,
  Link,
  Paper,
  TextField,
  Typography,
} from '@mui/material';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { login, saveSession } from '../services/authService';

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const justRegistered = location.state?.registered;

  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  function validate() {
    const e = {};
    if (!form.email.trim()) e.email = 'El email es requerido';
    if (!form.password) e.password = 'La contraseña es requerida';
    return e;
  }

  function handleChange(e) {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    setErrors((prev) => ({ ...prev, [name]: '' }));
    setApiError('');
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const fieldErrors = validate();
    if (Object.keys(fieldErrors).length) { setErrors(fieldErrors); return; }
    setLoading(true);
    try {
      const data = await login(form);
      saveSession(data);
      navigate('/dashboard');
    } catch (err) {
      if (err.status === 401) {
        setApiError('Credenciales incorrectas. Verifica tu email y contraseña.');
      } else if (err.data) {
        setApiError(Object.values(err.data).flat().join(' ') || 'Error al iniciar sesión.');
      } else {
        setApiError('Error de conexión. Intenta de nuevo.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        background: (t) =>
          `linear-gradient(135deg, ${t.palette.primary.dark} 0%, ${t.palette.primary.main} 100%)`,
      }}
    >
      <Container maxWidth="sm">
        <Paper elevation={6} sx={{ p: { xs: 3, sm: 5 } }}>
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
            <Box sx={{ bgcolor: 'primary.main', borderRadius: '50%', p: 1.5, mb: 1, display: 'flex' }}>
              <LockOutlinedIcon sx={{ color: 'primary.contrastText', fontSize: 32 }} />
            </Box>
            <Typography variant="h5" fontWeight={700} color="primary.dark">
              VaultChain
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" mt={0.5}>
              Iniciar sesión
            </Typography>
          </Box>

          {justRegistered && (
            <Alert severity="success" sx={{ mb: 2 }}>
              ¡Cuenta creada exitosamente! Ingresa tus credenciales.
            </Alert>
          )}
          {apiError && <Alert severity="error" sx={{ mb: 2 }}>{apiError}</Alert>}

          <Box component="form" onSubmit={handleSubmit} noValidate>
            <TextField
              fullWidth label="Correo electrónico" name="email" type="email"
              value={form.email} onChange={handleChange}
              error={!!errors.email} helperText={errors.email}
              margin="normal" autoComplete="email" autoFocus
            />
            <TextField
              fullWidth label="Contraseña" name="password"
              type={showPassword ? 'text' : 'password'}
              value={form.password} onChange={handleChange}
              error={!!errors.password} helperText={errors.password}
              margin="normal" autoComplete="current-password"
              slotProps={{
                input: {
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowPassword((s) => !s)} edge="end">
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
            />

            <Button type="submit" fullWidth variant="contained" size="large"
              disabled={loading} sx={{ mt: 3, mb: 2 }}>
              {loading ? <CircularProgress size={24} color="inherit" /> : 'Iniciar sesión'}
            </Button>

            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                ¿No tienes cuenta?{' '}
                <Link component={RouterLink} to="/register" fontWeight={600}>
                  Regístrate
                </Link>
              </Typography>
            </Box>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}
