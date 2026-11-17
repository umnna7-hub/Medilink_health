import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { useNavigate } from "react-router-dom";
import { apiFetch } from "../api";
import "./Auth.css";

function dashboardPath(role) {
  if (role === "admin") return "/admin-dashboard";
  if (role === "doctor") return "/doctor-dashboard";
  return "/patient-dashboard";
}

function MfaSetup() {
  const navigate = useNavigate();
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [savedCodes, setSavedCodes] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    apiFetch("/api/mfa/enroll", { method: "POST" })
      .then(async (response) => {
        const data = await response.json();
        if (response.status === 401) {
          navigate("/login", { replace: true });
          return null;
        }
        if (!response.ok) {
          throw new Error(data.message || "Unable to start MFA setup.");
        }
        if (active && data) setSetup(data);
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
  }, [navigate]);

  const copyText = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value);
      setError("");
    } catch {
      setError(`Could not copy ${label}. Select and copy it manually.`);
    }
  };

  const confirmCode = async (event) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const response = await apiFetch("/api/mfa/confirm", {
        method: "POST",
        body: JSON.stringify({ totp_code: code }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || "Unable to confirm authenticator code.");
      }
      sessionStorage.setItem("user", JSON.stringify(data.user));
      setRecoveryCodes(data.recovery_codes);
    } catch (requestError) {
      setError(requestError.message || "Unable to confirm MFA setup.");
    } finally {
      setSubmitting(false);
    }
  };

  const downloadCodes = () => {
    const file = new Blob(
      [`MediLink Health recovery codes\n\n${recoveryCodes.join("\n")}\n`],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = "medilink-recovery-codes.txt";
    link.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return <main className="auth-page">Preparing MFA setup...</main>;
  }

  return (
    <main className="auth-page">
      <section className="auth-card onboarding-card">
        <div className="auth-heading">
          <span className="auth-icon">🔒</span>
          <h1>Secure your account</h1>
          <p>Use an authenticator app to scan the QR code.</p>
        </div>

        {error && <p className="auth-error" role="alert">{error}</p>}

        {!setup && !recoveryCodes && (
          <p className="auth-error">MFA setup could not be loaded.</p>
        )}

        {setup && !recoveryCodes && (
          <>
            <div className="onboarding-qr">
              <QRCodeSVG value={setup.provisioning_uri} size={210} />
            </div>
            <p className="onboarding-note">
              Scan this with your authenticator app. If scanning is unavailable,
              enter this setup key manually.
            </p>
            <div className="onboarding-secret">
              <code>{setup.manual_key}</code>
              <button
                type="button"
                className="secondary-button"
                onClick={() => copyText(setup.manual_key, "setup key")}
              >
                Copy key
              </button>
            </div>
            <form onSubmit={confirmCode}>
              <label htmlFor="mfa-confirm-code">First authenticator code</label>
              <input
                id="mfa-confirm-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={(event) => setCode(
                  event.target.value.replace(/\D/g, "").slice(0, 6)
                )}
                required
              />
              <button type="submit" disabled={submitting || code.length !== 6}>
                {submitting ? "Verifying..." : "Confirm and continue"}
              </button>
            </form>
          </>
        )}

        {recoveryCodes && (
          <div className="recovery-codes">
            <h2>Save your recovery codes</h2>
            <p>
              These codes are shown once. Store them somewhere private; each
              code can be used one time if you cannot access your authenticator.
            </p>
            <ol>
              {recoveryCodes.map((recoveryCode) => (
                <li key={recoveryCode}><code>{recoveryCode}</code></li>
              ))}
            </ol>
            <div className="onboarding-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => copyText(recoveryCodes.join("\n"), "recovery codes")}
              >
                Copy codes
              </button>
              <button
                type="button"
                className="secondary-button"
                onClick={downloadCodes}
              >
                Download codes
              </button>
            </div>
            <label className="saved-codes-check">
              <input
                type="checkbox"
                checked={savedCodes}
                onChange={(event) => setSavedCodes(event.target.checked)}
              />
              I saved these
            </label>
            <button
              type="button"
              disabled={!savedCodes}
              onClick={() => navigate(
                dashboardPath(JSON.parse(
                  sessionStorage.getItem("user") || "null"
                )?.role),
                { replace: true }
              )}
            >
              Continue to dashboard
            </button>
          </div>
        )}
      </section>
    </main>
  );
}

export default MfaSetup;
