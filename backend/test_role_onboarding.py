import hashlib
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import urlparse

import jwt
import pyotp
import pytest
from cryptography.fernet import Fernet

import app as backend


def utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class OnboardingCursor:
    def __init__(self, state):
        self.state = state
        self.result = None
        self.rows = []
        self.rowcount = 0
        self.lastrowid = None

    def execute(self, query, params=None):
        normalized = " ".join(query.split())
        self.result = None
        self.rows = []
        self.rowcount = 0

        if "FROM revoked_tokens" in normalized:
            return
        if normalized.startswith(
            "SELECT user_id, role, account_status, session_version"
        ):
            self.result = self.state["users"].get(int(params[0]))
        elif normalized.startswith(
            "SELECT failed_count, locked_until FROM login_attempts"
        ):
            self.result = self.state["attempts"].get(params[0])
        elif normalized.startswith(
            "SELECT user_id, full_name, email, password_hash"
        ):
            self.result = self.state["users_by_email"].get(params[0])
        elif normalized.startswith("INSERT INTO login_attempts"):
            email = params[0]
            attempt = self.state["attempts"].setdefault(
                email, {"failed_count": 0, "locked_until": None}
            )
            attempt["failed_count"] += 1
        elif normalized.startswith("UPDATE login_attempts SET failed_count = 0"):
            attempt = self.state["attempts"].get(params[0])
            if attempt:
                attempt.update(failed_count=0, locked_until=None)
        elif normalized.startswith("INSERT INTO invite_rate_limits"):
            key = params[0]
            record = self.state["rate_limits"].setdefault(
                key,
                {"request_count": 0, "window_started_at": utcnow_naive()},
            )
            if record["window_started_at"] < utcnow_naive() - timedelta(minutes=1):
                record.update(request_count=1, window_started_at=utcnow_naive())
            else:
                record["request_count"] += 1
        elif normalized.startswith(
            "SELECT request_count FROM invite_rate_limits"
        ):
            self.result = self.state["rate_limits"].get(params[0])
        elif normalized.startswith("SELECT hospital_id FROM hospitals"):
            self.result = (
                {"hospital_id": params[0]}
                if params[0] in self.state["hospitals"]
                else None
            )
        elif normalized.startswith("INSERT INTO users"):
            full_name, email, password_hash, role = params[:4]
            user_id = self.state["next_user_id"]
            self.state["next_user_id"] += 1
            account_status = (
                "pending"
                if "'pending'" in normalized
                else (params[4] if len(params) > 4 else "active")
            )
            user = {
                "user_id": user_id,
                "full_name": full_name,
                "email": email,
                "password_hash": password_hash,
                "role": role,
                "account_status": account_status,
                "session_version": 0,
                "mfa_secret": None,
                "mfa_secret_format": "fernet",
                "mfa_confirmed_at": None,
            }
            self.state["users"][user_id] = user
            self.state["users_by_email"][email] = user
            self.lastrowid = user_id
        elif normalized.startswith("INSERT INTO doctors"):
            full_name, specialty, hospital_id, user_id = params
            self.state["doctors"][user_id] = {
                "full_name": full_name,
                "specialty": specialty,
                "hospital_id": hospital_id,
                "is_active": False,
            }
        elif normalized.startswith("INSERT INTO user_invites"):
            user_id, token_hash, created_by = params
            invite_id = self.state["next_invite_id"]
            self.state["next_invite_id"] += 1
            self.state["invites"][token_hash] = {
                "invite_id": invite_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "created_by": created_by,
                "expires_at": utcnow_naive() + timedelta(hours=48),
                "used_at": None,
            }
        elif normalized.startswith("SELECT u.full_name, u.email, u.role"):
            invite = self.state["invites"].get(params[0])
            user = self.state["users"].get(invite["user_id"]) if invite else None
            if (
                invite
                and user
                and invite["used_at"] is None
                and invite["expires_at"] > utcnow_naive()
                and user["account_status"] == "pending"
            ):
                self.result = {
                    "full_name": user["full_name"],
                    "email": user["email"],
                    "role": user["role"],
                }
        elif normalized.startswith("SELECT i.invite_id, i.user_id"):
            invite = self.state["invites"].get(params[0])
            user = self.state["users"].get(invite["user_id"]) if invite else None
            if (
                invite
                and user
                and invite["used_at"] is None
                and invite["expires_at"] > utcnow_naive()
                and user["account_status"] == "pending"
            ):
                self.result = {
                    **invite,
                    "full_name": user["full_name"],
                    "email": user["email"],
                    "role": user["role"],
                    "account_status": user["account_status"],
                    "session_version": user["session_version"],
                }
        elif normalized.startswith("UPDATE users SET password_hash"):
            password_hash, user_id = params
            user = self.state["users"].get(user_id)
            if user and user["account_status"] == "pending":
                user["password_hash"] = password_hash
                user["account_status"] = "active"
                self.rowcount = 1
        elif normalized.startswith("UPDATE doctors SET is_active = TRUE"):
            user = self.state["doctors"].get(params[0])
            if user:
                user["is_active"] = True
        elif normalized.startswith("UPDATE user_invites SET used_at"):
            invite_id = params[0]
            invite = next(
                (
                    value for value in self.state["invites"].values()
                    if value["invite_id"] == invite_id
                ),
                None,
            )
            if invite and invite["used_at"] is None:
                invite["used_at"] = utcnow_naive()
                self.rowcount = 1

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class OnboardingConnection:
    def __init__(self, state):
        self.state = state

    def cursor(self, dictionary=False):
        return OnboardingCursor(self.state)

    def start_transaction(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def onboarding(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", key)
    state = {
        "users": {},
        "users_by_email": {},
        "attempts": {},
        "rate_limits": {},
        "invites": {},
        "doctors": {},
        "hospitals": {5},
        "next_user_id": 1,
        "next_invite_id": 1,
    }
    original_testing = backend.app.config["TESTING"]
    backend.app.config["TESTING"] = True
    with patch.object(
        backend,
        "get_db_connection",
        side_effect=lambda: OnboardingConnection(state),
    ), patch.object(
        backend,
        "write_audit_log",
        return_value=True,
    ), patch.object(
        backend,
        "check_password_hash",
        side_effect=lambda password_hash, password: password == "correct-password",
    ):
        yield backend.app.test_client(), state, key
    backend.app.config["TESTING"] = original_testing


def add_user(state, role, email):
    user_id = state["next_user_id"]
    state["next_user_id"] += 1
    user = {
        "user_id": user_id,
        "full_name": "Test User",
        "email": email,
        "password_hash": "test-hash",
        "role": role,
        "account_status": "active",
        "session_version": 0,
        "mfa_secret": None,
        "mfa_secret_format": "fernet",
        "mfa_confirmed_at": None,
    }
    state["users"][user_id] = user
    state["users_by_email"][email] = user
    return user


def auth_headers(user):
    token = jwt.encode(
        {
            "sub": str(user["user_id"]),
            "role": user["role"],
            "jti": "onboarding-test",
            "sv": 0,
            "purpose": "session",
            "exp": int(time.time()) + 60,
        },
        backend.app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def test_public_registration_remains_patient_only_for_privileged_role_values(
    onboarding,
):
    client, state, _ = onboarding
    for role in ("doctor", "admin"):
        response = client.post(
            "/api/register",
            json={
                "full_name": "Public User",
                "email": f"{role}@example.test",
                "password": "correct-password",
                "role": role,
            },
        )
        assert response.status_code == 201
        created = state["users_by_email"][f"{role}@example.test"]
        assert created["role"] == "patient"


@pytest.mark.parametrize("role", ["admin", "doctor"])
def test_staff_password_alone_never_creates_full_session(onboarding, role):
    client, state, key = onboarding
    user = add_user(state, role, f"{role}@example.test")

    response = client.post(
        "/api/login",
        json={"email": user["email"], "password": "correct-password"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "mfa_setup_required"
    cookies = "\n".join(response.headers.getlist("Set-Cookie"))
    assert "medilink_mfa_setup=" in cookies
    assert not any(
        cookie.startswith("medilink_session=")
        and cookie.split("=", 1)[1].split(";", 1)[0]
        for cookie in response.headers.getlist("Set-Cookie")
    )
    assert key not in cookies
    setup_token = next(
        cookie.split("=", 1)[1].split(";", 1)[0]
        for cookie in response.headers.getlist("Set-Cookie")
        if cookie.startswith("medilink_mfa_setup=")
        and cookie.split("=", 1)[1].split(";", 1)[0]
    )
    protected = client.get(
        "/api/me",
        headers={"Authorization": f"Bearer {setup_token}"},
    )
    assert protected.status_code == 401


def test_confirmed_staff_login_requires_second_factor(onboarding):
    client, state, _ = onboarding
    user = add_user(state, "doctor", "doctor@example.test")
    secret = pyotp.random_base32()
    user["mfa_secret"] = backend._encrypt_mfa_secret(secret)
    user["mfa_confirmed_at"] = utcnow_naive()

    response = client.post(
        "/api/login",
        json={"email": user["email"], "password": "correct-password"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "mfa_required"
    assert not any(
        cookie.startswith("medilink_session=")
        and cookie.split("=", 1)[1].split(";", 1)[0]
        for cookie in response.headers.getlist("Set-Cookie")
    )


def test_non_admin_cannot_invite(onboarding):
    client, state, _ = onboarding
    patient = add_user(state, "patient", "patient@example.test")

    response = client.post(
        "/api/admin/users/invite",
        json={
            "full_name": "New Doctor",
            "email": "new-doctor@example.test",
            "role": "doctor",
            "specialty": "Cardiology",
            "hospital_id": 5,
        },
        headers=auth_headers(patient),
    )

    assert response.status_code == 403
    assert state["invites"] == {}


def create_invitation(client, state):
    admin = add_user(state, "admin", "admin@example.test")
    admin["mfa_secret"] = "encrypted-test-secret"
    admin["mfa_confirmed_at"] = utcnow_naive()
    response = client.post(
        "/api/admin/users/invite",
        json={
            "full_name": "Invited Admin",
            "email": "invited-admin@example.test",
            "role": "admin",
        },
        headers=auth_headers(admin),
    )
    assert response.status_code == 201
    invite_url = response.get_json()["invite_url"]
    token = urlparse(invite_url).path.rsplit("/", 1)[-1]
    return token, state["users_by_email"]["invited-admin@example.test"]


def test_invite_accept_activates_and_requires_limited_mfa_setup(onboarding):
    client, state, _ = onboarding
    token, invited_user = create_invitation(client, state)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    assert token_hash in state["invites"]
    assert token not in state["invites"]
    details = client.get(f"/api/invites/{token}")
    assert details.status_code == 200
    assert details.get_json()["invite"] == {
        "full_name": "Invited Admin",
        "email": "invited-admin@example.test",
        "role": "admin",
    }

    accepted = client.post(
        f"/api/invites/{token}/accept",
        json={"password": "new-secure-password"},
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["status"] == "mfa_setup_required"
    assert invited_user["account_status"] == "active"
    assert state["invites"][token_hash]["used_at"] is not None
    cookie = "\n".join(accepted.headers.getlist("Set-Cookie"))
    assert "medilink_mfa_setup=" in cookie
    assert not any(
        entry.startswith("medilink_session=")
        and entry.split("=", 1)[1].split(";", 1)[0]
        for entry in accepted.headers.getlist("Set-Cookie")
    )

    reused = client.post(
        f"/api/invites/{token}/accept",
        json={"password": "another-secure-password"},
    )
    assert reused.status_code == 400
    assert reused.get_json()["message"] == "Invalid or expired invitation"


def test_expired_invite_uses_same_invalid_or_expired_response(onboarding):
    client, state, _ = onboarding
    token, _ = create_invitation(client, state)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    state["invites"][token_hash]["expires_at"] = utcnow_naive() - timedelta(
        seconds=1
    )

    lookup = client.get(f"/api/invites/{token}")
    accepted = client.post(
        f"/api/invites/{token}/accept",
        json={"password": "new-secure-password"},
    )

    assert lookup.status_code == 400
    assert accepted.status_code == 400
    assert lookup.get_json()["message"] == "Invalid or expired invitation"
    assert accepted.get_json()["message"] == "Invalid or expired invitation"


def test_invite_endpoints_are_rate_limited_by_client(onboarding):
    client, _, _ = onboarding
    invalid_token = "A" * 32

    for _ in range(20):
        response = client.get(f"/api/invites/{invalid_token}")
        assert response.status_code == 400

    limited = client.get(f"/api/invites/{invalid_token}")
    assert limited.status_code == 429
