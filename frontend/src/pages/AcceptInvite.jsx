import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiFetch } from "../api";
import "./Auth.css";

function AcceptInvite() {
  const { token } = useParams();
  const navigate = useNavigate();
  const [invite, setInvite] = useState(null);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    apiFetch(`/api/invites/${encodeURIComponent(token)}`)
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.message || "Invalid or expired invitation.");
        }
        if (active) setInvite(data.invite);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [token]);

  const handleAccept = async (event) => {
    event.preventDefault();
    setError("");
    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8 || password.length > 128) {
      setError("Password must be between 8 and 128 characters.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await apiFetch(
        `/api/invites/${encodeURIComponent(token)}/accept`,
        {
          method: "POST",
          body: JSON.stringify({ password }),
        }
      );
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || "Unable to accept invitation.");
      }
      sessionStorage.setItem("user", JSON.stringify(data.user));
      navigate("/mfa-setup", { replace: true });
    } catch (requestError) {
      setError(requestError.message || "Unable to accept invitation.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card">
        <Link to="/" className="auth-back">← Back to Home</Link>
        <div className="auth-heading">
          <span className="auth-icon">✚</span>
          <h1>Accept invitation</h1>
          <p>Set your password, then secure your account with MFA.</p>
        </div>
        {loading ? (
          <p>Checking invitation...</p>
        ) : invite ? (
          <>
            <dl className="onboarding-details">
              <div><dt>Name</dt><dd>{invite.full_name}</dd></div>
              <div><dt>Email</dt><dd>{invite.email}</dd></div>
              <div><dt>Role</dt><dd>{invite.role}</dd></div>
            </dl>
            <form onSubmit={handleAccept}>
              <label htmlFor="invite-password">Password</label>
              <input
                id="invite-password"
                type="password"
                autoComplete="new-password"
                minLength={8}
                maxLength={128}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
              <label htmlFor="invite-confirmation">Confirm password</label>
              <input
                id="invite-confirmation"
                type="password"
                autoComplete="new-password"
                minLength={8}
                maxLength={128}
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                required
              />
              {error && <p className="auth-error" role="alert">{error}</p>}
              <button type="submit" disabled={submitting}>
                {submitting ? "Accepting..." : "Set password and continue"}
              </button>
            </form>
          </>
        ) : (
          <p className="auth-error" role="alert">
            {error || "Invalid or expired invitation."}
          </p>
        )}
      </section>
    </main>
  );
}

export default AcceptInvite;
