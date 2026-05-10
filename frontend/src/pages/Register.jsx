import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { register } from '../services/authService';

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ display_name: '', email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  function validate() {
    const e = {};
    if (!form.display_name.trim()) e.display_name = 'El nombre es requerido';
    if (!form.email.trim())        e.email = 'El email es requerido';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = 'Email inválido';
    if (!form.password)            e.password = 'La contraseña es requerida';
    else if (form.password.length < 8) e.password = 'Mínimo 8 caracteres';
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
      await register(form);
      navigate('/login', { state: { registered: true } });
    } catch (err) {
      if (err.status === 409) {
        setApiError('Este email ya está registrado.');
      } else if (err.data) {
        setApiError(Object.values(err.data).flat().join(' ') || 'Error al registrar.');
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
          <p>Crear cuenta</p>
        </div>

        {apiError && <div className="alert alert-error">{apiError}</div>}

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="display_name">Nombre completo</label>
            <input
              id="display_name" name="display_name" autoComplete="name" autoFocus
              value={form.display_name} onChange={handleChange}
              className={errors.display_name ? 'err' : ''}
            />
            {errors.display_name && <span className="helper err">{errors.display_name}</span>}
          </div>

          <div className="field">
            <label htmlFor="email">Correo electrónico</label>
            <input
              id="email" name="email" type="email" autoComplete="email"
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
                autoComplete="new-password" className={`has-eye${errors.password ? ' err' : ''}`}
                value={form.password} onChange={handleChange}
              />
              <button type="button" className="eye-btn" onClick={() => setShowPassword((s) => !s)}>
                {showPassword ? '🙈' : '👁'}
              </button>
            </div>
            {errors.password && <span className="helper err">{errors.password}</span>}
          </div>

          <button type="submit" className="btn btn-primary btn-full mt-3" disabled={loading}>
            {loading ? <span className="spinner" /> : 'Registrarse'}
          </button>

          <p className="text-sm text-center mt-3">
            ¿Ya tienes cuenta?{' '}
            <Link to="/login" className="link">Iniciar sesión</Link>
          </p>
        </form>
      </div>
    </div>
  );
}
