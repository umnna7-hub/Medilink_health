
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { API_BASE_URL } from "../config";
import "./Auth.css";

function Register() {
  const navigate = useNavigate();
const [showPassword, setShowPassword] = useState(false);
const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          full_name: fullName,
          email,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || "Registration failed.");
        return;
      }

      navigate("/login");
    } catch (err) {
      setError("Unable to connect to the server. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <Link to="/" className="auth-back">← Back to Home</Link>

        <div className="auth-heading">
          <span className="auth-icon">✚</span>
          <h1>Create Account</h1>
          <p>Join MediLink Health and manage your healthcare.</p>
        </div>

        <form onSubmit={handleRegister}>
          <label htmlFor="fullName">Full Name</label>
          <input
            id="fullName"
            type="text"
            placeholder="Enter your full name"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            required
          />

          <label htmlFor="registerEmail">Email Address</label>
          <input
            id="registerEmail"
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
<label htmlFor="registerPassword">Password</label>

<div className="password-input-wrapper">
  <input
    id="registerPassword"
    type={showPassword ? "text" : "password"}
    placeholder="At least 8 characters"
    value={password}
    onChange={(e) => setPassword(e.target.value)}
    minLength={8}
    required
  />

  <button
    type="button"
    className="password-toggle"
    onClick={() => setShowPassword(!showPassword)}
    aria-label={showPassword ? "Hide password" : "Show password"}
  >
    {showPassword ? "◉" : "◎"}
  </button>
</div>

<label htmlFor="confirmPassword">Confirm Password</label>

<div className="password-input-wrapper">
  <input
    id="confirmPassword"
    type={showConfirmPassword ? "text" : "password"}
    placeholder="Re-enter your password"
    value={confirmPassword}
    onChange={(e) => setConfirmPassword(e.target.value)}
    required
  />

  <button
    type="button"
    className="password-toggle"
    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
    aria-label={showConfirmPassword ? "Hide password" : "Show password"}
  >
    {showConfirmPassword ? "◉" : "◎"}
  </button>
</div>

          {error && <p className="auth-error">{error}</p>}

          <button type="submit" disabled={loading}>
            {loading ? "Creating Account..." : "Create Account"}
          </button>
        </form>

        <p className="auth-switch">
          Already have an account? <Link to="/login">Log In</Link>
        </p>
      </div>
    </div>
  );
}

export default Register;
