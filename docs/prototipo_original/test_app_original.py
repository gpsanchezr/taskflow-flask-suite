import re
import tempfile
import unittest
from pathlib import Path

from app import create_app


class TaskAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": "test-key",
                "DATABASE": str(Path(self.temp_dir.name) / "test.sqlite3"),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def register(self, username):
        return self.client.post(
            "/register",
            data={"username": username, "password": "secure-pass-123"},
            follow_redirects=True,
        )

    def test_user_can_manage_task(self):
        self.register("ana")
        response = self.client.post(
            "/tasks",
            data={"title": "Preparar presentación", "notes": "Borrador"},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from app import get_db

            task_id = get_db().execute("SELECT id FROM tasks").fetchone()["id"]

        self.client.post(f"/tasks/{task_id}/toggle")
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("Preparar presentación", page)
        self.client.post(
            f"/tasks/{task_id}/edit",
            data={"title": "Presentación", "notes": ""},
        )
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("Presentación", page)
        self.client.post(f"/tasks/{task_id}/delete")
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("Presentación", page)

    def test_users_cannot_access_each_others_tasks(self):
        self.register("ana")
        self.client.post("/tasks", data={"title": "Privada", "notes": ""})
        with self.app.app_context():
            from app import get_db

            task_id = get_db().execute("SELECT id FROM tasks").fetchone()["id"]

        self.client.post("/logout")
        self.register("luis")
        edit_response = self.client.get(f"/tasks/{task_id}/edit")
        toggle_response = self.client.post(f"/tasks/{task_id}/toggle")
        delete_response = self.client.post(f"/tasks/{task_id}/delete")
        self.assertEqual(edit_response.status_code, 404)
        self.assertEqual(toggle_response.status_code, 404)
        self.assertEqual(delete_response.status_code, 404)
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("Privada", page)

    def test_registration_form_includes_csrf_token(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        page = self.client.get("/register").get_data(as_text=True)
        token_match = re.search(
            r'<input type="hidden" name="csrf_token" value="([^"]+)"', page
        )
        self.assertIsNotNone(token_match)
        response = self.client.post(
            "/register",
            data={
                "username": "maria",
                "password": "secure-pass-123",
                "csrf_token": token_match.group(1),
            },
        )
        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
