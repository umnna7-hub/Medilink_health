
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import logo from "../../medilink-health-transparent (1).png";
import { API_BASE_URL } from "../config";
import "./login.css";

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          ...(totpCode ? { totp_code: totpCode } : {}),
        }),
      });

      const data = await response.json();

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
              />
            </div>

            <div className="login-field">
              <label htmlFor="totp-code">Authenticator Code (if enabled)</label>
              <input
                id="totp-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                placeholder="Enter your 6-digit code"
                value={totpCode}
                onChange={(e) => setTotpCode(
                  e.target.value.replace(/\D/g, "").slice(0, 6)
                )}
              />
            </div>

            {error && <div className="login-error">{error}</div>}

            <button type="submit" className="login-button" disabled={loading}>
              {loading ? "Signing In..." : "Sign In"}
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
