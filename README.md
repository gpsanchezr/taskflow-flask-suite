# Pausa

Aplicación web de tareas hecha con Flask: registro, inicio de sesión y tareas
separadas por usuario (crear, editar, completar y eliminar).

> Este proyecto nació como prototipo de *vibe coding* (Taller 3, SENA · ADSO) y
> luego fue **auditado**. Esta versión incluye las correcciones de la auditoría;
> la copia sin modificar del prototipo está en `docs/prototipo_original/`.

## Tecnologías

Python 3.11+, Flask, Flask-Login, Flask-WTF (CSRF), Flask-Limiter, SQLite.

## Estructura

```
app.py              aplicación (rutas, base de datos y arranque)
templates/          auth.html, base.html, index.html, edit_task.html
static/styles.css   estilos
tests/test_app.py   pruebas automatizadas (unittest)
docs/prototipo_original/   prototipo original, sin modificar (referencia de la auditoría)
```

## Ejecutar ambas aplicaciones en paralelo (PowerShell, Windows)

Se requiere Python 3.11 o posterior. Abre PowerShell en la carpeta raíz del
proyecto, la que contiene `app.py`. Usa `python` en los comandos; no hace falta
el lanzador `py`.

### 1. Pausa (versión corregida y auditada)

En la primera terminal, crea y activa el entorno virtual, instala las
dependencias y configura las variables necesarias para ejecutar Pausa en el
puerto 5001:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:PORT = "5001"
python app.py
```

Abre <http://127.0.0.1:5001> y deja esta terminal abierta mientras uses Pausa.
La `SECRET_KEY` es obligatoria. El comando anterior genera una para esta sesión
de PowerShell; vuelve a definirla si cierras la terminal y arrancas Pausa de
nuevo. No publiques ni compartas su valor.

### 2. Gestor de Tareas (prototipo original)

Abre una segunda terminal de PowerShell en la misma carpeta raíz del proyecto.
Activa el entorno virtual ya creado y ejecuta el archivo del prototipo original:

```powershell
.\.venv\Scripts\Activate.ps1
python .\docs\prototipo_original\app_original.py
```

Abre <http://127.0.0.1:5000> y deja también esta terminal abierta. El prototipo
usa el puerto 5000 de Flask por defecto, mientras Pausa usa el 5001.

Si PowerShell impide activar el entorno virtual, ejecuta lo siguiente en esa
terminal y vuelve a activar el entorno:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Para detener una aplicación, pulsa `Ctrl+C` en su terminal.

- La base SQLite de Pausa se crea sola en `instance/tasks.sqlite3` (no se versiona).
- Variables opcionales para Pausa: `DATABASE_PATH`, `FLASK_DEBUG=1` (solo en
  desarrollo) y `SESSION_COOKIE_SECURE=1` (cuando se sirva por HTTPS).

## Pruebas

```powershell
python -m unittest discover -s tests -v
```

Las pruebas usan una base de datos temporal y **mantienen activo el CSRF**.

## Medidas de seguridad

- Contraseñas guardadas solo como hash (Werkzeug); longitud de 8 a 128 caracteres.
- `SECRET_KEY` solo desde el entorno; sin valor por defecto.
- CSRF activo en todos los formularios (Flask-WTF), incluido el cierre de sesión.
- Límite de intentos: 5 inicios de sesión fallidos por minuto y 10 registros por hora por IP (Flask-Limiter).
- Cada consulta filtra por `user_id`; una tarea ajena responde 404.
- Consultas SQL parametrizadas; plantillas con escape automático de Jinja.
- Cookie de sesión `HttpOnly` y `SameSite=Lax`; tamaño máximo de petición de 64 KB.

## Limitaciones conocidas

- Todo el código vive en `app.py` (conviene separarlo en módulos si el proyecto crece).
- El límite de intentos usa memoria del proceso: con varios procesos se necesita Redis u otro almacén compartido.
- Registro solo con nombre de usuario: el mensaje de error ya no confirma si existe,
  pero la enumeración total solo se evita con registro por correo verificado.
- Sin recuperación de contraseña ni cierre de sesiones en otros dispositivos.
