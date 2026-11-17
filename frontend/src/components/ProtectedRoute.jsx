import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { apiFetch } from "../api";

function ProtectedRoute({ allowedRoles, children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const handleUnauthorized = () => {
      if (active) {
        sessionStorage.clear();
        setUser(null);
        setLoading(false);
      }
    };

    window.addEventListener("medilink:unauthorized", handleUnauthorized);
    apiFetch("/api/me")
      .then(async (response) => {
        if (!response.ok) {
          sessionStorage.clear();
          return null;
        }
        const data = await response.json();
        if (
          !data.user ||
          !allowedRoles.includes(data.user.role)
        ) {
          sessionStorage.clear();
          return null;
        }
        sessionStorage.setItem("user", JSON.stringify(data.user));
        return data.user;
      })
      .then((verifiedUser) => {
        if (active) setUser(verifiedUser);
      })
      .catch(() => {
        if (active) sessionStorage.clear();
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
      window.removeEventListener(
        "medilink:unauthorized",
        handleUnauthorized
      );
    };
  }, [allowedRoles]);

  if (loading) {
    return <main className="auth-page">Verifying your session...</main>;
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default ProtectedRoute;
