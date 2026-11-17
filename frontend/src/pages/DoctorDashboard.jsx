import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiFetch } from "../api";
import "./Dashboard.css";

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value || "Not available")
    : date.toLocaleString("en-PK", {
      dateStyle: "medium",
      timeStyle: "short",
    });
}

function DoctorDashboard() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [appointments, setAppointments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([
      apiFetch("/api/doctor/profile"),
      apiFetch("/api/doctor/appointments"),
    ])
      .then(async ([profileResponse, appointmentResponse]) => {
        const [profileData, appointmentData] = await Promise.all([
          profileResponse.json(),
          appointmentResponse.json(),
        ]);
        if (!profileResponse.ok || !appointmentResponse.ok) {
          throw new Error(
            profileData.message ||
            appointmentData.message ||
            "Unable to load your doctor dashboard."
          );
        }
        if (active) {
          setProfile(profileData.profile);
          setAppointments(appointmentData.appointments || []);
        }
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
  }, []);

  const logout = async () => {
    try {
      await apiFetch("/api/logout", { method: "POST" });
    } catch (requestError) {
      setError(requestError.message || "Unable to complete secure logout.");
    } finally {
      sessionStorage.clear();
      navigate("/login", { replace: true });
    }
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner" />
        <p>Loading your doctor dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-page">
      <header className="dashboard-navbar">
        <a href="#overview" className="dashboard-brand">
          <span className="brand-symbol">M</span>
          <span>
            <strong>MediLink Health</strong>
            <small>Doctor Portal</small>
          </span>
        </a>
        <div className="dashboard-nav-actions">
          <span>{profile?.full_name || "Doctor"}</span>
          <button onClick={logout} className="logout-button">Log Out</button>
        </div>
      </header>

      <main className="dashboard-main" id="overview">
        <section className="dashboard-heading">
          <div>
            <span className="eyebrow">DOCTOR DASHBOARD</span>
            <h1>Welcome, {profile?.full_name || "Doctor"}</h1>
            <p>Your profile and assigned appointments.</p>
          </div>
        </section>

        {error && <p className="section-message error-text" role="alert">{error}</p>}

        {profile && (
          <section className="profile-card">
            <div className="profile-avatar">
              {profile.full_name?.trim().charAt(0).toUpperCase() || "D"}
            </div>
            <div className="profile-information">
              <h2>{profile.full_name}</h2>
              <p>{profile.email}</p>
              <span className="profile-role">
                {profile.specialty} · {profile.hospital_name || "Hospital not assigned"}
              </span>
              {profile.hospital_city && <small>{profile.hospital_city}</small>}
            </div>
          </section>
        )}

        <section className="dashboard-section">
          <div className="section-heading">
            <div>
              <span className="eyebrow">YOUR SCHEDULE</span>
              <h2>Appointments</h2>
              <p>Only appointments assigned to your doctor profile are shown.</p>
            </div>
          </div>
          {!appointments.length && !error && (
            <div className="empty-state"><p>No appointments are assigned yet.</p></div>
          )}
          <div className="record-list">
            {appointments.map((appointment) => (
              <article className="record-card" key={appointment.appointment_id}>
                <div className="record-card-top">
                  <div>
                    <span className="record-label">
                      APPOINTMENT #{appointment.appointment_id}
                    </span>
                    <h3>{appointment.patient_name}</h3>
                    <p>{appointment.hospital_name || "Hospital not listed"}</p>
                  </div>
                  <span className="record-date">
                    {appointment.status} · {formatDate(appointment.appointment_date)}
                  </span>
                </div>
                <div className="record-details-grid">
                  <p><strong>Reason</strong><span>{appointment.reason || "Not provided"}</span></p>
                  {appointment.hospital_city && (
                    <p><strong>City</strong><span>{appointment.hospital_city}</span></p>
                  )}
                </div>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

export default DoctorDashboard;
