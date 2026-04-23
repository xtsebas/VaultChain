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

## Flujo de desarrollo con migraciones

Las migraciones se generan en el entorno local y se aplican automáticamente al iniciar Docker.

**Al modificar un modelo:**

```bash
# 1. Activar el entorno virtual local (no dentro de Docker)
cd backend
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 2. Generar la migración — solo requiere el entorno virtual, no la base de datos
python manage.py makemigrations

# 3. Incluir en el commit tanto el modelo como el archivo de migración generado
git add .
git commit -m "..."
```

**Para levantar el proyecto con las migraciones aplicadas:**

```bash
docker-compose up --build
# El comando migrate se ejecuta automaticamente al iniciar el backend
```

**Consideraciones para el equipo:**
- `makemigrations` debe ejecutarse siempre en el entorno local con el venv
- `migrate` es ejecutado por Docker al arrancar — no se debe correr manualmente
- Los archivos de migración deben commitearse junto con el modelo que los origina
- No se debe ejecutar `makemigrations` dentro del contenedor, ya que los archivos generados quedan aislados y no se reflejan en el repositorio
---

## Tests

Los tests corren dentro del contenedor Docker. Asegúrate de tener los contenedores levantados antes de ejecutarlos:

```bash
docker-compose up -d
```

**Todos los tests:**
```bash
docker exec vaultchain_backend python manage.py test
```

**Por módulo:**
```bash
docker exec vaultchain_backend python manage.py test auth_module
docker exec vaultchain_backend python manage.py test blockchain
docker exec vaultchain_backend python manage.py test signatures
docker exec vaultchain_backend python manage.py test crypto_module
```

**Por archivo de test:**
```bash
docker exec vaultchain_backend python manage.py test auth_module.tests.test_register
docker exec vaultchain_backend python manage.py test auth_module.tests.test_login
docker exec vaultchain_backend python manage.py test auth_module.tests.test_public_key
```

**Un test específico:**
```bash
docker exec vaultchain_backend python manage.py test auth_module.tests.test_register.RegisterSuccessTest.test_returns_201_with_expected_fields
```

El patrón para un test específico es siempre:
```
modulo.tests.archivo.Clase.metodo
```

---

## Equipo

- Sebastian Huertas
- Josue Marroquin
- Gerson Ramirez