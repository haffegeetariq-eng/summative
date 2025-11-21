from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import check_password_hash, generate_password_hash


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret-key"  # Replace in production with env var
    app.config["DATABASE"] = Path(app.instance_path) / "users.db"

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE"])

    class ProfileForm(FlaskForm):
        full_name = StringField(
            "Full Name",
            validators=[DataRequired(), Length(min=2, max=80)],
        )
        email = StringField(
            "Email Address",
            validators=[DataRequired(), Email(), Length(max=120)],
        )
        bio = StringField(
            "Short Bio",
            validators=[Length(max=240)],
        )

    class RegistrationForm(ProfileForm):
        password = PasswordField(
            "Password",
            validators=[DataRequired(), Length(min=6, max=128)],
        )
        confirm_password = PasswordField(
            "Confirm Password",
            validators=[
                DataRequired(),
                EqualTo("password", message="Passwords must match"),
            ],
        )
        submit = SubmitField("Register")

    class UpdateProfileForm(ProfileForm):
        submit = SubmitField("Update Profile")

    class LoginForm(FlaskForm):
        email = StringField(
            "Email Address",
            validators=[DataRequired(), Email(), Length(max=120)],
        )
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Log In")

    def db_action(fn: Callable[[sqlite3.Cursor], None]) -> None:
        """Helper to open a connection, execute work, and close neatly."""
        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        try:
            fn(cursor)
            connection.commit()
        finally:
            connection.close()

    @app.route("/")
    def home():
        return redirect(url_for("register"))

    @app.context_processor
    def inject_current_user():
        """Expose logged-in metadata to templates without manual passing."""
        return {
            "current_user_id": session.get("user_id"),
            "current_user_name": session.get("user_name"),
        }

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            # Normalize user-provided data so stored rows stay clean/consistent.
            user_data = (
                form.full_name.data.strip(),
                form.email.data.lower(),
                form.bio.data.strip(),
                generate_password_hash(form.password.data.strip()),
            )

            new_user_id: int | None = None

            def insert(cursor: sqlite3.Cursor) -> None:
                cursor.execute(
                    """
                    INSERT INTO users (full_name, email, bio, password_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    user_data,
                )
                nonlocal new_user_id
                new_user_id = cursor.lastrowid

            try:
                db_action(insert)
            except sqlite3.IntegrityError:
                flash("That email is already registered. Please log in.", "error")
                return render_template("register.html", form=form)
            if new_user_id:
                session["user_id"] = new_user_id
                session["user_name"] = user_data[0]
            flash("Registration successful!", "success")
            return redirect(url_for("profiles"))

        return render_template("register.html", form=form)

    @app.route("/profiles")
    def profiles():
        records: list[sqlite3.Row] = []

        def fetch(cursor: sqlite3.Cursor) -> None:
            # Pull every profile to render a simple dashboard.
            cursor.execute(
                "SELECT id, full_name, email, bio, created_at FROM users ORDER BY created_at DESC"
            )
            records.extend(cursor.fetchall())

        db_action(fetch)
        return render_template("profiles.html", profiles=records)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user: dict | None = None

            def fetch(cursor: sqlite3.Cursor) -> None:
                cursor.execute(
                    "SELECT * FROM users WHERE email = ?", (form.email.data.lower(),)
                )
                row = cursor.fetchone()
                if row:
                    nonlocal user
                    user = dict(row)

            db_action(fetch)

            if user and user.get("password_hash") and check_password_hash(
                user["password_hash"], form.password.data
            ):
                session["user_id"] = user["id"]
                session["user_name"] = user["full_name"]
                flash("Welcome back!", "success")
                return redirect(url_for("profiles"))

            flash("Invalid email or password.", "error")

        return render_template("login.html", form=form)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/profiles/<int:user_id>/edit", methods=["GET", "POST"])
    def edit_profile(user_id: int):
        # Load user first so we can pre-populate the form and handle 404-like cases.
        user: dict | None = None

        def fetch(cursor: sqlite3.Cursor) -> None:
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                nonlocal user
                user = dict(row)

        db_action(fetch)

        if user is None:
            flash("User not found.", "error")
            return redirect(url_for("profiles"))
        if session.get("user_id") != user_id:
            flash("Please log in as this user before editing the profile.", "error")
            return redirect(url_for("login"))

        form = UpdateProfileForm(data=user)

        if request.method == "POST" and form.validate_on_submit():
            # Persist the updated values while keeping the same row id.
            updated = (
                form.full_name.data.strip(),
                form.email.data.lower(),
                form.bio.data.strip(),
                user_id,
            )

            def update(cursor: sqlite3.Cursor) -> None:
                cursor.execute(
                    """
                    UPDATE users
                    SET full_name = ?, email = ?, bio = ?
                    WHERE id = ?
                    """,
                    updated,
                )

            db_action(update)
            flash("Profile updated.", "success")
            return redirect(url_for("profiles"))

        return render_template("edit_profile.html", form=form, user=user)

    return app


def init_db(db_path: Path) -> None:
    """Create tables if they do not exist; keeps demo setup simple."""
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    # Using IF NOT EXISTS lets us call init_db repeatedly without errors.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            bio TEXT,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute("PRAGMA table_info(users)")
    columns = {row[1] for row in cursor.fetchall()}
    if "password_hash" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''"
        )
    connection.commit()
    connection.close()


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)

