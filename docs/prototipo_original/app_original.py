import os
import sqlite3
from pathlib import Path

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Inicia sesión para continuar."
login_manager.login_message_category = "info"
csrf = CSRFProtect()


class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            completed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    db.commit()


def create_app(test_config=None):
    flask_app = Flask(__name__, instance_relative_config=True)
    default_database = str(Path(flask_app.instance_path) / "tasks.sqlite3")
    flask_app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
        DATABASE=os.environ.get("DATABASE_PATH", default_database),
    )
    if test_config:
        flask_app.config.update(test_config)

    Path(flask_app.instance_path).mkdir(parents=True, exist_ok=True)
    database_path = Path(flask_app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    login_manager.init_app(flask_app)
    csrf.init_app(flask_app)
    flask_app.teardown_appcontext(close_db)

    with flask_app.app_context():
        init_db()

    @flask_app.get("/")
    def index():
        if not current_user.is_authenticated:
            return redirect(url_for("login"))

        selected_filter = request.args.get("filter", "all")
        where = "user_id = ?"
        params = [current_user.id]
        if selected_filter == "active":
            where += " AND completed = 0"
        elif selected_filter == "completed":
            where += " AND completed = 1"
        else:
            selected_filter = "all"

        tasks = get_db().execute(
            "SELECT id, title, notes, completed, created_at "
            f"FROM tasks WHERE {where} "
            "ORDER BY completed ASC, created_at DESC, id DESC",
            params,
        ).fetchall()
        counts = get_db().execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN completed = 0 THEN 1 ELSE 0 END) AS active, "
            "SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) AS completed "
            "FROM tasks WHERE user_id = ?",
            (current_user.id,),
        ).fetchone()
        return render_template(
            "index.html",
            tasks=tasks,
            counts=counts,
            selected_filter=selected_filter,
        )

    @flask_app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            error = None
            if len(username) < 3 or len(username) > 32:
                error = "El usuario debe tener entre 3 y 32 caracteres."
            elif len(password) < 8:
                error = "La contraseña debe tener al menos 8 caracteres."
            elif get_db().execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone():
                error = "Ese nombre de usuario ya está en uso."

            if error:
                flash(error, "error")
            else:
                cursor = get_db().execute(
                    "INSERT INTO users (username, password_hash) "
                    "VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                get_db().commit()
                login_user(User(cursor.lastrowid, username))
                return redirect(url_for("index"))
        return render_template("auth.html", mode="register")

    @flask_app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, username, password_hash "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if user is None or not check_password_hash(
                user["password_hash"], password
            ):
                flash("Usuario o contraseña incorrectos.", "error")
            else:
                login_user(User(user["id"], user["username"]), remember=False)
                return redirect(url_for("index"))
        return render_template("auth.html", mode="login")

    @flask_app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @flask_app.post("/tasks")
    @login_required
    def create_task():
        title = request.form.get("title", "").strip()
        notes = request.form.get("notes", "").strip()
        if not title or len(title) > 120:
            flash("Escribe un título de hasta 120 caracteres.", "error")
        elif len(notes) > 500:
            flash("Las notas no pueden superar los 500 caracteres.", "error")
        else:
            get_db().execute(
                "INSERT INTO tasks (user_id, title, notes) VALUES (?, ?, ?)",
                (current_user.id, title, notes),
            )
            get_db().commit()
            flash("Tarea añadida.", "success")
        return redirect(url_for("index"))

    def owned_task(task_id):
        task = get_db().execute(
            "SELECT id, title, notes, completed FROM tasks "
            "WHERE id = ? AND user_id = ?",
            (task_id, current_user.id),
        ).fetchone()
        if task is None:
            abort(404)
        return task

    @flask_app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_task(task_id):
        task = owned_task(task_id)
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            notes = request.form.get("notes", "").strip()
            if not title or len(title) > 120:
                flash("Escribe un título de hasta 120 caracteres.", "error")
            elif len(notes) > 500:
                flash(
                    "Las notas no pueden superar los 500 caracteres.", "error"
                )
            else:
                get_db().execute(
                    "UPDATE tasks SET title = ?, notes = ? "
                    "WHERE id = ? AND user_id = ?",
                    (title, notes, task_id, current_user.id),
                )
                get_db().commit()
                flash("Cambios guardados.", "success")
                return redirect(url_for("index"))
        return render_template("edit_task.html", task=task)

    @flask_app.post("/tasks/<int:task_id>/toggle")
    @login_required
    def toggle_task(task_id):
        task = owned_task(task_id)
        get_db().execute(
            "UPDATE tasks SET completed = ? WHERE id = ? AND user_id = ?",
            (0 if task["completed"] else 1, task_id, current_user.id),
        )
        get_db().commit()
        return redirect(url_for("index"))

    @flask_app.post("/tasks/<int:task_id>/delete")
    @login_required
    def delete_task(task_id):
        owned_task(task_id)
        get_db().execute(
            "DELETE FROM tasks WHERE id = ? AND user_id = ?",
            (task_id, current_user.id),
        )
        get_db().commit()
        flash("Tarea eliminada.", "success")
        return redirect(url_for("index"))

    return flask_app


@login_manager.user_loader
def load_user(user_id):
    row = get_db().execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return User(row["id"], row["username"]) if row else None


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
