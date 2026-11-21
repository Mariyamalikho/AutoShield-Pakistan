from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired(), Length(min=3, max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField("Email Address", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Auditor Account")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError("This username is already registered.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.strip().lower()).first():
            raise ValidationError("This email address is already in use.")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash("This account has been deactivated.", "danger")
                return render_template("auth/login.html", form=form)

            login_user(user, remember=form.remember.data)
            user.last_login = datetime.now(timezone.utc)

            # Audit log
            log = AuditLog(
                user_id=user.id,
                action="user_login",
                target_resource="auth_system",
                ip_address=request.remote_addr,
                details=f"Successful sign-in for user {user.username}",
            )
            db.session.add(log)
            db.session.commit()

            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.index"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    # If first user, make admin, otherwise auditor
    first_user = User.query.first() is None
    form = RegisterForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="admin" if first_user else "auditor",
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        # Audit log
        log = AuditLog(
            user_id=user.id,
            action="user_registered",
            target_resource="auth_system",
            ip_address=request.remote_addr,
            details=f"Account created with role '{user.role}'",
        )
        db.session.add(log)
        db.session.commit()

        flash("Account created successfully. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form, is_first_user=first_user)


@auth_bp.route("/logout")
@login_required
def logout():
    log = AuditLog(
        user_id=current_user.id,
        action="user_logout",
        target_resource="auth_system",
        ip_address=request.remote_addr,
        details="User signed out",
    )
    db.session.add(log)
    db.session.commit()
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
