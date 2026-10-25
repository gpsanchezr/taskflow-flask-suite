"""Pruebas automatizadas de Pausa (unittest, sin dependencias extra).

La protección CSRF permanece ACTIVA en todas las pruebas: cada POST envía el
token real que la aplicación entrega en sus formularios.
"""
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import create_app, get_db

PASSWORD = "secure-pass-123"
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class BaseCase(unittest.TestCase):
    rate_limit = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-key",
                "DATABASE": str(Path(self.temp_dir.name) / "test.sqlite3"),
                "RATELIMIT_ENABLED": self.rate_limit,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- utilidades -------------------------------------------------------
    def token(self, client=None):
        client = client or self.client
        html = client.get("/login", follow_redirects=True).get_data(as_text=True)
        match = TOKEN_RE.search(html)
        self.assertIsNotNone(match, "la página no incluye csrf_token")
        return match.group(1)

    def post(self, path, data=None, client=None, **kwargs):
        client = client or self.client
        data = dict(data or {})
        data["csrf_token"] = self.token(client)
        return client.post(path, data=data, **kwargs)

    def register(self, username, password=PASSWORD, client=None):
        return self.post(
            "/register",
            {"username": username, "password": password},
            client=client,
        )

    def login(self, username, password=PASSWORD, client=None):
        return self.post(
            "/login",
            {"username": username, "password": password},
            client=client,
        )

    def add_task(self, title="Tarea", notes="", client=None):
        return self.post("/tasks", {"title": title, "notes": notes}, client=client)

    def query(self, sql, params=()):
        with self.app.app_context():
            return get_db().execute(sql, params).fetchall()

    def first_task_id(self):
        return self.query("SELECT id FROM tasks ORDER BY id")[0]["id"]


class AuthTests(BaseCase):
    def test_register_logs_the_user_in(self):
        response = self.register("ana")
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("ana", page)

    def test_password_is_stored_as_hash(self):
        self.register("ana")
        stored = self.query("SELECT password_hash FROM users")[0][0]
        self.assertNotEqual(stored, PASSWORD)
        self.assertNotIn(PASSWORD, stored)
        self.assertRegex(stored, r"^(scrypt|pbkdf2):")

    def test_register_validates_username_and_password_length(self):
        casos = {
            "usuario corto": ("ab", PASSWORD),
            "usuario largo": ("u" * 33, PASSWORD),
            "contraseña corta": ("ana", "1234567"),
            "contraseña demasiado larga": ("ana", "x" * 129),
        }
        for nombre, (user, pwd) in casos.items():
            with self.subTest(nombre):
                response = self.register(user, pwd)
                self.assertEqual(response.status_code, 200)
        self.assertEqual(self.query("SELECT COUNT(*) FROM users")[0][0], 0)

    def test_register_accepts_limit_values(self):
        self.assertEqual(self.register("abc", "x" * 8).status_code, 302)
        other = self.app.test_client()
        self.assertEqual(self.register("u" * 32, "y" * 128, client=other).status_code, 302)

    def test_duplicate_username_is_rejected_case_insensitive(self):
        self.register("ana")
        self.post("/logout")
        response = self.register("ANA")
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("ya está en uso", page)
        self.assertEqual(self.query("SELECT COUNT(*) FROM users")[0][0], 1)

    def test_wrong_password_and_unknown_user_share_the_same_message(self):
        self.register("ana")
        self.post("/logout")
        mala = self.login("ana", "otra-clave-123").get_data(as_text=True)
        inexistente = self.login("nadie", PASSWORD).get_data(as_text=True)
        mensaje = "Usuario o contraseña incorrectos."
        self.assertIn(mensaje, mala)
        self.assertIn(mensaje, inexistente)

    def test_login_and_logout(self):
        self.register("ana")
        self.post("/logout")
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.login("ana").status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_session_cookie_flags(self):
        response = self.register("ana")
        cookie = " ".join(response.headers.getlist("Set-Cookie"))
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_secret_key_is_required(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SECRET_KEY", None)
            with self.assertRaises(RuntimeError):
                create_app({"DATABASE": str(Path(self.temp_dir.name) / "x.sqlite3")})


class RateLimitTests(BaseCase):
    rate_limit = True

    def test_login_is_blocked_after_five_failed_attempts(self):
        self.register("ana")
        self.post("/logout")
        estados = [self.login("ana", "incorrecta-123").status_code for _ in range(5)]
        self.assertEqual(estados, [200] * 5)
        self.assertEqual(self.login("ana", "incorrecta-123").status_code, 429)
        # Con el límite alcanzado, ni siquiera la clave correcta entra.
        self.assertEqual(self.login("ana").status_code, 429)


class TaskTests(BaseCase):
    def test_full_crud_flow(self):
        self.register("ana")
        self.assertEqual(self.add_task("Preparar presentación", "Borrador").status_code, 302)
        task_id = self.first_task_id()
        self.assertIn("Preparar presentación", self.client.get("/").get_data(as_text=True))

        self.post(f"/tasks/{task_id}/toggle")
        self.assertEqual(self.query("SELECT completed FROM tasks")[0][0], 1)
        self.post(f"/tasks/{task_id}/toggle")
        self.assertEqual(self.query("SELECT completed FROM tasks")[0][0], 0)

        self.post(f"/tasks/{task_id}/edit", {"title": "Presentación final", "notes": ""})
        self.assertEqual(self.query("SELECT title FROM tasks")[0][0], "Presentación final")

        self.post(f"/tasks/{task_id}/delete")
        self.assertEqual(self.query("SELECT COUNT(*) FROM tasks")[0][0], 0)

    def test_task_validation_limits(self):
        self.register("ana")
        invalidos = {
            "título vacío": ("   ", ""),
            "título de 121": ("t" * 121, ""),
            "notas de 501": ("ok", "n" * 501),
        }
        for nombre, (titulo, notas) in invalidos.items():
            with self.subTest(nombre):
                self.add_task(titulo, notas)
        self.assertEqual(self.query("SELECT COUNT(*) FROM tasks")[0][0], 0)
        self.add_task("t" * 120, "n" * 500)
        self.assertEqual(self.query("SELECT COUNT(*) FROM tasks")[0][0], 1)

    def test_edit_validation_keeps_previous_values(self):
        self.register("ana")
        self.add_task("Original", "nota")
        task_id = self.first_task_id()
        self.post(f"/tasks/{task_id}/edit", {"title": "x" * 121, "notes": ""})
        self.assertEqual(self.query("SELECT title FROM tasks")[0][0], "Original")

    def test_tasks_persist_after_logout_and_login(self):
        self.register("ana")
        self.add_task("Persistente")
        self.post("/logout")
        self.login("ana")
        self.assertIn("Persistente", self.client.get("/").get_data(as_text=True))

    def test_anonymous_user_is_redirected_to_login(self):
        for path in ("/", "/tasks/1/edit"):
            with self.subTest(path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])


class IsolationTests(BaseCase):
    def test_other_user_cannot_read_or_change_a_task(self):
        self.register("ana")
        self.add_task("Privada", "secreto")
        task_id = self.first_task_id()
        self.post("/logout")

        self.register("luis")
        self.assertEqual(self.client.get(f"/tasks/{task_id}/edit").status_code, 404)
        self.assertEqual(
            self.post(f"/tasks/{task_id}/edit", {"title": "Hackeada", "notes": ""}).status_code, 404
        )
        self.assertEqual(self.post(f"/tasks/{task_id}/toggle").status_code, 404)
        self.assertEqual(self.post(f"/tasks/{task_id}/delete").status_code, 404)
        self.assertNotIn("Privada", self.client.get("/").get_data(as_text=True))
        fila = self.query("SELECT title, completed FROM tasks")[0]
        self.assertEqual((fila["title"], fila["completed"]), ("Privada", 0))


class CsrfTests(BaseCase):
    def test_post_without_token_is_rejected(self):
        self.assertEqual(
            self.client.post("/register", data={"username": "ana", "password": PASSWORD}).status_code,
            400,
        )
        self.register("ana")
        sin_token = self.client.post("/tasks", data={"title": "Sin token", "notes": ""})
        self.assertEqual(sin_token.status_code, 400)
        self.assertEqual(self.query("SELECT COUNT(*) FROM tasks")[0][0], 0)

    def test_post_with_invalid_token_is_rejected(self):
        self.register("ana")
        respuesta = self.client.post(
            "/tasks", data={"title": "Falso", "notes": "", "csrf_token": "token-falso"}
        )
        self.assertEqual(respuesta.status_code, 400)

    def test_every_form_carries_a_token(self):
        paginas = {"login": self.client.get("/login"), "registro": self.client.get("/register")}
        self.register("ana")
        self.add_task("Algo")
        paginas["tablero"] = self.client.get("/")
        paginas["edición"] = self.client.get(f"/tasks/{self.first_task_id()}/edit")
        for nombre, respuesta in paginas.items():
            with self.subTest(nombre):
                self.assertRegex(respuesta.get_data(as_text=True), TOKEN_RE)


if __name__ == "__main__":
    unittest.main()
