import { useState } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { login, saveSession, verifyMFACode } from '../services/authService';

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const justRegistered = location.state?.registered;

  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // MFA step state
  const [mfaStep, setMfaStep] = useState(false);
  const [pendingEmail, setPendingEmail] = useState('');
  const [savedPassword, setSavedPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');

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
      if (data.mfa_required) {
        setPendingEmail(data.email);
        setSavedPassword(form.password);
        setMfaStep(true);
        return;
      }
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

  async function handleTOTP(e) {
    e.preventDefault();
    if (!totpCode.trim()) return;
    setLoading(true);
    setApiError('');
    try {
      const data = await verifyMFACode(pendingEmail, totpCode);
      saveSession(data, savedPassword);
      navigate('/dashboard');
    } catch (err) {
      if (err.status === 401) {
        setApiError('Código TOTP incorrecto o expirado.');
      } else {
        setApiError('Error al verificar el código. Intenta de nuevo.');
      }
      setTotpCode('');
    } finally {
      setLoading(false);
    }
  }

  if (mfaStep) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-logo">
            <div className="auth-logo-icon">🔐</div>
            <h1>VaultChain</h1>
            <p>Verificación MFA</p>
          </div>

          <div className="alert alert-info">
            Abre Google Authenticator e ingresa el código de 6 dígitos para <strong>{pendingEmail}</strong>.
          </div>

          {apiError && <div className="alert alert-error">{apiError}</div>}

          <form onSubmit={handleTOTP} noValidate>
            <div className="field">
              <label htmlFor="totp">Código TOTP</label>
              <input
                id="totp"
                name="totp"
                type="text"
                inputMode="numeric"
                maxLength={6}
                autoFocus
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => { setTotpCode(e.target.value.replace(/\D/g, '')); setApiError(''); }}
                placeholder="000000"
                style={{ letterSpacing: '0.3em', fontSize: '1.4rem', textAlign: 'center' }}
              />
            </div>

            <button type="submit" className="btn btn-primary btn-full mt-3" disabled={loading || totpCode.length !== 6}>
              {loading ? <span className="spinner" /> : 'Verificar código'}
            </button>

            <button
              type="button"
              className="btn btn-ghost btn-full mt-2"
              onClick={() => { setMfaStep(false); setApiError(''); setTotpCode(''); }}
            >
              ← Volver al inicio de sesión
            </button>
          </form>
        </div>
      </div>
    );
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
