import { useState } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
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
    if (!form.password)     e.password = 'La contraseña es requerida';
    return e;
  }

  function handleChange(e) {
    const { name, value } = e.target;
    setForm((p) => ({ ...p, [name]: value }));
    setErrors((p) => ({ ...p, [name]: '' }));
    setApiError('');
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const fe = validate();
    if (Object.keys(fe).length) { setErrors(fe); return; }
    setLoading(true);
    try {
      const data = await login(form);
      saveSession(data, form.password);
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
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <div className="auth-logo-icon">🔒</div>
          <h1>VaultChain</h1>
          <p>Iniciar sesión</p>
        </div>

        {justRegistered && (
          <div className="alert alert-success">¡Cuenta creada exitosamente! Ingresa tus credenciales.</div>
        )}
        {apiError && <div className="alert alert-error">{apiError}</div>}

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="email">Correo electrónico</label>
            <input
              id="email" name="email" type="email" autoComplete="email" autoFocus
              value={form.email} onChange={handleChange}
              className={errors.email ? 'err' : ''}
            />
            {errors.email && <span className="helper err">{errors.email}</span>}
          </div>

          <div className="field">
            <label htmlFor="password">Contraseña</label>
            <div className="field-input-wrap">
              <input
                id="password" name="password" type={showPassword ? 'text' : 'password'}
                autoComplete="current-password" className={`has-eye${errors.password ? ' err' : ''}`}
                value={form.password} onChange={handleChange}
              />
              <button type="button" className="eye-btn" onClick={() => setShowPassword((s) => !s)}>
                {showPassword ? '🙈' : '👁'}
              </button>
            </div>
            {errors.password && <span className="helper err">{errors.password}</span>}
          </div>

          <button type="submit" className="btn btn-primary btn-full mt-3" disabled={loading}>
            {loading ? <span className="spinner" /> : 'Iniciar sesión'}
          </button>

          <p className="text-sm text-center mt-3">
            ¿No tienes cuenta?{' '}
            <Link to="/register" className="link">Regístrate</Link>
          </p>
        </form>
      </div>
    </div>
  );
}
