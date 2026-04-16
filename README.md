# VaultChain

Sistema de mensajeria segura con registro inmutable para el Ministerio de Finanzas Publicas de Guatemala.

Desarrollado por VaultChain S.A. como prototipo funcional que implementa cifrado hibrido, firmas digitales, autenticacion multifactor y un mini-blockchain de auditoria.

---

## Stack

- **Backend**: Django (Python)
- **Frontend**: React + Vite
- **Base de datos**: PostgreSQL
- **Contenedores**: Docker + Docker Compose

---

## Modulos

| Modulo | Descripcion |
|--------|-------------|
| 1 | Gestion de identidad, hashing de passwords, generacion de llaves RSA/ECC |
| 2 | Cifrado hibrido AES-256-GCM + RSA-OAEP |
| 3 | Firmas digitales ECDSA + Mini-blockchain SHA-256 |
| 4 | MFA (TOTP), JWT, integracion completa, despliegue |

---

## Estructura del repositorio

```
VaultChain/
├── backend/
│   ├── manage.py
│   ├── requirements.txt
│   ├── vaultchain/          # Settings del proyecto Django
│   ├── auth_module/         # Modulo 1: Identidad
│   ├── crypto_module/       # Modulo 2: Cifrado hibrido
│   ├── signatures/          # Modulo 3: Firmas digitales
│   ├── blockchain/          # Modulo 3: Mini-blockchain
│   └── api/                 # Endpoints REST
├── frontend/                # React + Vite
├── docs/
│   ├── arquitectura.md
│   └── analisis.md
├── schema.sql
├── docker-compose.yml
├── Dockerfile
└── .gitignore
```

---

## Instalacion y uso

### Requisitos

- Python 3.11+
- Node.js 22.12+
- Docker + Docker Compose

### Levantar con Docker

```bash
docker-compose up --build
```

### Desarrollo local

**Backend:**
```bash
cd backend
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## Equipo

- Sebastian Huertas
- Josue Marroquin
- Gerson Ramirez