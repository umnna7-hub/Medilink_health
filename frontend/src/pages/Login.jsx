
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import logo from "../../medilink-health-transparent (1).png";
import { apiFetch } from "../api";
import "./login.css";

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [step, setStep] = useState("credentials");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await apiFetch("/api/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          ...(step === "mfa" && !useRecoveryCode && totpCode
            ? { totp_code: totpCode }
            : {}),
          ...(step === "mfa" && useRecoveryCode && recoveryCode
            ? { recovery_code: recoveryCode }
            : {}),
        }),
      });

      const data = await response.json();

      if (response.ok && data.status === "mfa_required") {
        setStep("mfa");
        setTotpCode("");
        setRecoveryCode("");
        return;
      }

      if (response.ok && data.status === "mfa_setup_required") {
        sessionStorage.setItem("user", JSON.stringify(data.user));
        navigate("/mfa-setup");
        return;
      }

      if (!response.ok) {
        setError(data.message || data.error || "Invalid email or password.");
        return;
      }

      sessionStorage.setItem("user", JSON.stringify(data.user));

      if (data.user.role === "admin") {
        navigate("/admin-dashboard");
      } else if (data.user.role === "doctor") {
        navigate("/doctor-dashboard");
      } else {
        navigate("/patient-dashboard");
      }
    } catch {
      setError("Unable to connect to the server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-layout">
        <div className="login-intro">
          <img src={logo} alt="MediLink Health" className="login-main-logo" />

          <span className="login-overline">EXCELLENCE IN HEALTHCARE DELIVERY</span>

          <h1>Healthcare access, <span>made simple.</span></h1>

          <p>
            Access qualified physicians, schedule consultations, and manage
            your medical care through a single, secure platform.
          </p>

          <div className="login-trust">
            <span>✓</span>
            Secure access to your healthcare services
          </div>
        </div>

        <div className="login-card">
          <div className="login-heading">
            <span className="login-small-label">MEDILINK HEALTH PORTAL</span>
            <h2>Welcome Back</h2>
            <p>Sign in to your MediLink Health account.</p>
          </div>

          <form onSubmit={handleLogin} className="login-form">
            <div className="login-field">
              <label htmlFor="email">Email Address</label>
              <input
                id="email"
                type="email"
                placeholder="Enter your email address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
                disabled={step === "mfa"}
              />
            </div>

            <div className="login-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                disabled={step === "mfa"}
              />
            </div>

            {step === "mfa" && (
              <>
                <div className="login-field">
                  <label htmlFor="mfa-code">
                    {useRecoveryCode ? "Recovery Code" : "Authenticator Code"}
                  </label>
                  <input
                    id="mfa-code"
                    type="text"
                    inputMode={useRecoveryCode ? "text" : "numeric"}
                    autoComplete="one-time-code"
                    maxLength={useRecoveryCode ? 64 : 6}
                    placeholder={
                      useRecoveryCode
                        ? "Enter one unused recovery code"
                        : "Enter your 6-digit code"
                    }
                    value={useRecoveryCode ? recoveryCode : totpCode}
                    onChange={(event) => {
                      if (useRecoveryCode) {
                        setRecoveryCode(event.target.value);
                      } else {
                        setTotpCode(
                          event.target.value.replace(/\D/g, "").slice(0, 6)
                        );
                      }
                    }}
                    required
                  />
                </div>
                <button
                  type="button"
                  className="login-secondary-button"
                  onClick={() => {
                    setUseRecoveryCode(!useRecoveryCode);
                    setTotpCode("");
                    setRecoveryCode("");
                    setError("");
                  }}
                >
                  {useRecoveryCode
                    ? "Use authenticator code instead"
                    : "Use a recovery code"}
                </button>
                <button
                  type="button"
                  className="login-secondary-button"
                  onClick={() => {
                    setStep("credentials");
                    setUseRecoveryCode(false);
                    setTotpCode("");
                    setRecoveryCode("");
                    setError("");
                  }}
                >
                  Back to sign in
                </button>
              </>
            )}

            {error && <div className="login-error">{error}</div>}

            <button type="submit" className="login-button" disabled={loading}>
              {loading
                ? "Verifying..."
                : step === "mfa"
                  ? "Verify and Sign In"
                  : "Sign In"}
              {!loading && <span>→</span>}
            </button>
          </form>

          <div className="login-register">
            Don't have an account? <Link to="/register">Sign Up</Link>
          </div>

          <div className="login-security">
            <span>🔒</span> Your account and health information are protected.
          </div>
        </div>
      </section>
    </main>
  );
}

export default Login;
