import { useState } from 'react';
import SessionWidget from '../components/SessionWidget';
import Messaging from '../components/Messaging';
import Blockchain from '../components/Blockchain';
import { getSessionUser } from '../services/authService';

function initials(name = '') {
  return name.split(' ').slice(0, 2).map((w) => w[0]?.toUpperCase()).join('');
}

const TABS = [
  { id: 'messages',    label: '🔒 Mensajería' },
  { id: 'blockchain',  label: '⛓ Blockchain' },
];

export default function Dashboard() {
  const user = getSessionUser();
  const [profileOpen, setProfileOpen] = useState(false);
  const [activeTab, setActiveTab]     = useState('messages');

  return (
    <>
      <nav className="appbar">
        <span style={{ fontSize: 20 }}>🔒</span>
        <span className="appbar-title">VaultChain</span>
        <button
          className="appbar-btn"
          title="Crypto Log (Shift+I)"
          onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { shiftKey: true, key: 'I', bubbles: true }))}
        >
          {'</>'}
        </button>
        <div className="avatar" title="Mi perfil" onClick={() => setProfileOpen(true)}>
          {initials(user?.display_name)}
        </div>
      </nav>

      <SessionWidget open={profileOpen} onClose={() => setProfileOpen(false)} />

      <main className="main-content">
        <div className="welcome" style={{ marginBottom: 16 }}>
          <h2>Hola, {user?.display_name}</h2>
          <p>Bienvenido a VaultChain — Mensajería cifrada E2E</p>
        </div>

        <div className="dash-tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              className={`dash-tab${activeTab === tab.id ? ' dash-tab-active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'messages'   && <Messaging />}
        {activeTab === 'blockchain' && <Blockchain />}
      </main>
    </>
  );
}
