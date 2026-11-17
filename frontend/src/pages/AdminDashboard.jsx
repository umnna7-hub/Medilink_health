import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./AdminDashboard.css";

const API = import.meta.env.VITE_API_URL;

const NAV_ITEMS = [
  ["overview", "Overview", "OV"],
  ["hospitals", "Hospitals", "HO"],
  ["laboratories", "Laboratories", "LB"],
  ["doctors", "Doctors", "DR"],
  ["users", "Users", "US"],
  ["appointments", "Appointments", "AP"],
  ["medical-records", "Medical records", "MR"],
  ["lab-reports", "Lab reports", "LR"],
  ["payments", "Payments", "PY"],
  ["audit-logs", "Audit & security", "AU"],
];

const EMPTY_OVERVIEW = {
  total_hospitals: 0,
  active_hospitals: 0,
  total_laboratories: 0,
  active_laboratories: 0,
  total_users: 0,
  active_doctors: 0,
  total_appointments: 0,
  appointment_statuses: {},
  total_payments: 0,
  payment_statuses: {},
};

function StatusBadge({ value }) {
  const status = String(value || "unknown").toLowerCase().replaceAll(" ", "-");
  return <span className={`admin-status ${status}`}>{value || "Unknown"}</span>;
}

function TableMessage({ children, columns }) {
  return (
    <tr>
      <td className="admin-empty-cell" colSpan={columns}>{children}</td>
    </tr>
  );
}

function formatDate(value, dateOnly = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return dateOnly
    ? date.toLocaleDateString()
    : date.toLocaleString();
}

function AdminDashboard() {
  const navigate = useNavigate();
  const [user] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem("user") || "null");
    } catch {
      return null;
    }
  });
  const [section, setSection] = useState("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [overview, setOverview] = useState(EMPTY_OVERVIEW);
  const [activities, setActivities] = useState([]);
  const [users, setUsers] = useState([]);
  const [hospitals, setHospitals] = useState([]);
  const [laboratories, setLaboratories] = useState([]);
  const [doctors, setDoctors] = useState([]);
  const [appointments, setAppointments] = useState([]);
  const [medicalRecords, setMedicalRecords] = useState([]);
  const [labReports, setLabReports] = useState([]);
  const [payments, setPayments] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [appointmentFilters, setAppointmentFilters] = useState({
    hospital_id: "",
    doctor_id: "",
    patient_id: "",
    date: "",
    status: "",
    q: "",
  });
  const [hospitalDraft, setHospitalDraft] = useState(null);
  const [laboratoryDraft, setLaboratoryDraft] = useState(null);
  const [doctorDraft, setDoctorDraft] = useState(null);
  const [reportDraft, setReportDraft] = useState(null);
  const [doctorAppointments, setDoctorAppointments] = useState(null);

  const apiRequest = useCallback(async (path, options = {}) => {
    const response = await fetch(`${API}${path}`, {
      ...options,
      credentials: "include",
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        sessionStorage.clear();
        navigate("/login");
      }
      throw new Error(data.message || `Request failed (${response.status})`);
    }
    return data;
  }, [navigate]);

  const loadDashboard = useCallback(async () => {
    const resources = [
      ["overview", "/api/admin/overview", "overview"],
      ["users", "/api/admin/users", "users"],
      ["hospitals", "/api/admin/hospitals", "hospitals"],
      ["laboratories", "/api/admin/laboratories", "laboratories"],
      ["doctors", "/api/admin/doctors", "doctors"],
      ["appointments", "/api/admin/appointments", "appointments"],
      ["medicalRecords", "/api/admin/medical-records", "medical_records"],
      ["labReports", "/api/admin/lab-reports", "lab_reports"],
      ["payments", "/api/admin/payments", "payments"],
      ["auditLogs", "/api/admin/audit-logs", "audit_logs"],
    ];

    try {
      const results = await Promise.all(resources.map(async ([key, path]) => {
        try {
          return { key, data: await apiRequest(path) };
        } catch (requestError) {
          return { key, error: requestError.message };
        }
      }));
      const failures = [];
      results.forEach((result) => {
        if (result.error) {
          failures.push(`${result.key}: ${result.error}`);
          return;
        }
        const data = result.data;
        switch (result.key) {
          case "overview":
            setOverview(data.overview || EMPTY_OVERVIEW);
            setActivities(data.recent_activities || []);
            break;
          case "users":
            setUsers(data.users || []);
            break;
          case "hospitals":
            setHospitals(data.hospitals || []);
            break;
          case "laboratories":
            setLaboratories(data.laboratories || []);
            break;
          case "doctors":
            setDoctors(data.doctors || []);
            break;
          case "appointments":
            setAppointments(data.appointments || []);
            break;
          case "medicalRecords":
            setMedicalRecords(data.medical_records || []);
            break;
          case "labReports":
            setLabReports(data.lab_reports || []);
            break;
          case "payments":
            setPayments(data.payments || []);
            break;
          case "auditLogs":
            setAuditLogs(data.audit_logs || []);
            break;
          default:
            break;
        }
      });
      setError(failures.length
        ? `Some sections could not load: ${failures.join(" | ")}`
        : "");
    } finally {
      setLoading(false);
    }
  }, [apiRequest]);

  const refreshDashboard = () => {
    setLoading(true);
    setError("");
    loadDashboard();
  };

  useEffect(() => {
    if (!user || user.role !== "admin") {
      sessionStorage.clear();
      navigate("/login");
      return;
    }
    // Load external API state after authentication is established.
    // oxlint-disable-next-line react/set-state-in-effect
    loadDashboard();
  }, [loadDashboard, navigate, user]);

  const runAction = async (action, successMessage) => {
    setError("");
    setNotice("");
    try {
      await action();
      setNotice(successMessage);
      await loadDashboard();
      return true;
    } catch (actionError) {
      setError(actionError.message || "The requested action failed.");
      return false;
    }
  };

  const updateUserStatus = (userId, accountStatus) => runAction(
    () => apiRequest(`/api/admin/users/${userId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ account_status: accountStatus }),
    }),
    "Account status updated."
  );

  const toggleHospital = (hospital) => runAction(
    () => apiRequest(`/api/admin/hospitals/${hospital.hospital_id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: !hospital.is_active }),
    }),
    "Hospital status updated."
  );

  const toggleLaboratory = (laboratory) => runAction(
    () => apiRequest(`/api/admin/laboratories/${laboratory.lab_id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: !laboratory.is_active }),
    }),
    "Laboratory status updated."
  );

  const toggleDoctor = (doctor) => runAction(
    () => apiRequest(`/api/admin/doctors/${doctor.doctor_id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: !doctor.is_active }),
    }),
    "Doctor status updated."
  );

  const submitHospital = async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const editing = hospitalDraft?.hospital_id;
    const saved = await runAction(
      () => apiRequest(
        editing
          ? `/api/admin/hospitals/${editing}`
          : "/api/admin/hospitals",
        {
          method: editing ? "PATCH" : "POST",
          body: JSON.stringify(values),
        }
      ),
      editing ? "Hospital details saved." : "Hospital created."
    );
    if (saved) setHospitalDraft(null);
  };

  const submitLaboratory = async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const editing = laboratoryDraft?.lab_id;
    const saved = await runAction(
      () => apiRequest(
        editing
          ? `/api/admin/laboratories/${editing}`
          : "/api/admin/laboratories",
        {
          method: editing ? "PATCH" : "POST",
          body: JSON.stringify(values),
        }
      ),
      editing ? "Laboratory details saved." : "Laboratory created."
    );
    if (saved) setLaboratoryDraft(null);
  };

  const submitDoctor = async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const editing = doctorDraft?.doctor_id;
    if (editing) {
      delete values.email;
      delete values.password;
    }
    const saved = await runAction(
      () => apiRequest(
        editing ? `/api/admin/doctors/${editing}` : "/api/admin/doctors",
        {
          method: editing ? "PATCH" : "POST",
          body: JSON.stringify(values),
        }
      ),
      editing ? "Doctor details saved." : "Doctor account created."
    );
    if (saved) setDoctorDraft(null);
  };

  const submitAppointmentStatus = (appointmentId, status) => runAction(
    () => apiRequest(`/api/admin/appointments/${appointmentId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
    "Appointment status updated."
  );

  const submitReport = async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const saved = await runAction(
      () => apiRequest(`/api/admin/lab-reports/${reportDraft.report_id}`, {
        method: "PATCH",
        body: JSON.stringify(values),
      }),
      "Lab report metadata updated."
    );
    if (saved) setReportDraft(null);
  };

  const filterAppointments = async (event) => {
    event.preventDefault();
    const params = new URLSearchParams();
    Object.entries(appointmentFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    try {
      const data = await apiRequest(
        `/api/admin/appointments?${params.toString()}`
      );
      setAppointments(data.appointments || []);
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const viewDoctorAppointments = async (doctorId) => {
    try {
      const data = await apiRequest(
        `/api/admin/doctors/${doctorId}/appointments`
      );
      setDoctorAppointments({
        doctorId,
        appointments: data.appointments || [],
      });
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const logout = async () => {
    try {
      await fetch(`${API}/api/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (logoutError) {
      console.error("Logout request failed:", logoutError);
    } finally {
      sessionStorage.clear();
      navigate("/login");
    }
  };

  const filtered = (items, ...fields) => {
    const needle = search.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => fields.some((field) =>
      String(item[field] ?? "").toLowerCase().includes(needle)
    ));
  };

  const activeHospitals = useMemo(
    () => hospitals.filter((hospital) => hospital.is_active),
    [hospitals]
  );
  const title = NAV_ITEMS.find(([key]) => key === section)?.[1] || "Overview";

  if (loading) {
    return <div className="admin-loading">Loading MediLink Health administration…</div>;
  }

  return (
    <div className="admin-layout">
      <aside className="admin-sidebar">
        <a className="admin-brand" href="#overview" onClick={() => setSection("overview")}>
          <span className="admin-brand-symbol">M</span>
          <span>
            <strong>MediLink Health</strong>
            <small>Excellence in Healthcare Delivery</small>
          </span>
        </a>
        <div className="admin-sidebar-label">MANAGEMENT</div>
        <nav className="admin-side-nav" aria-label="Admin dashboard navigation">
          {NAV_ITEMS.map(([key, label, icon]) => (
            <button
              className={section === key ? "selected" : ""}
              key={key}
              onClick={() => {
                setSection(key);
                setSearch("");
              }}
              aria-current={section === key ? "page" : undefined}
            >
              <span className="admin-nav-icon" aria-hidden="true">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="admin-sidebar-footer">
          <span className="admin-avatar" aria-hidden="true">
            {user?.full_name?.trim().charAt(0).toUpperCase() || "A"}
          </span>
          <div className="admin-account">
            <strong>{user?.full_name || "Administrator"}</strong>
            <small>Administrator</small>
          </div>
          <button className="admin-logout" onClick={logout}>Log out</button>
        </div>
      </aside>

      <main className="admin-main">
        <header className="admin-topbar">
          <div>
            <span className="admin-eyebrow">MEDILINK HEALTH / ADMINISTRATION</span>
            <h1>{title}</h1>
          </div>
          <button className="admin-refresh" onClick={refreshDashboard}>Refresh data</button>
        </header>

        {error && <div className="admin-alert error" role="alert">{error}</div>}
        {notice && <div className="admin-alert success" role="status">{notice}</div>}

        {section === "overview" && (
          <>
            <section className="admin-welcome">
              <div>
                <span className="admin-eyebrow">SYSTEM OVERVIEW</span>
                <h2>Welcome, {user?.full_name || "Administrator"}</h2>
                <p>Manage MediLink Health services and monitor current activity.</p>
              </div>
              <div className="admin-welcome-mark" aria-hidden="true">ML</div>
            </section>
            <section className="admin-stats" aria-label="System statistics">
              <article className="admin-stat"><span className="stat-mark">HO</span><div><p>Hospitals</p><strong>{overview.total_hospitals}</strong><small>{overview.active_hospitals} active</small></div></article>
              <article className="admin-stat"><span className="stat-mark">LB</span><div><p>Laboratories</p><strong>{overview.total_laboratories}</strong><small>{overview.active_laboratories} active</small></div></article>
              <article className="admin-stat"><span className="stat-mark">US</span><div><p>Registered users</p><strong>{overview.total_users}</strong><small>All account roles</small></div></article>
              <article className="admin-stat"><span className="stat-mark">DR</span><div><p>Active doctors</p><strong>{overview.active_doctors}</strong><small>Available for booking</small></div></article>
              <article className="admin-stat"><span className="stat-mark">AP</span><div><p>Appointments</p><strong>{overview.total_appointments}</strong><small>{Object.entries(overview.appointment_statuses || {}).map(([status, count]) => `${status}: ${count}`).join(" · ") || "No appointments"}</small></div></article>
              <article className="admin-stat"><span className="stat-mark">PY</span><div><p>Payments</p><strong>{overview.total_payments}</strong><small>{Object.entries(overview.payment_statuses || {}).map(([status, count]) => `${status}: ${count}`).join(" · ") || "No payments"}</small></div></article>
            </section>
            <section className="admin-panel">
              <div className="panel-heading">
                <div><span className="admin-eyebrow">MONITORING</span><h2>Recent administrative and security activity</h2></div>
                <button className="text-button" onClick={() => setSection("audit-logs")}>View audit log</button>
              </div>
              <div className="admin-table-wrapper">
                <table>
                  <thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>Details</th><th>Date</th></tr></thead>
                  <tbody>
                    {activities.map((activity) => (
                      <tr key={activity.log_id}>
                        <td>{activity.actor_name || "System"}</td>
                        <td>{activity.action}</td>
                        <td>{activity.target_type || "—"}{activity.target_id ? ` #${activity.target_id}` : ""}</td>
                        <td>{activity.event_details || "—"}</td>
                        <td>{formatDate(activity.created_at)}</td>
                      </tr>
                    ))}
                    {!activities.length && <TableMessage columns={5}>No recent activity recorded.</TableMessage>}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        {section === "hospitals" && (
          <section className="admin-panel">
            <div className="panel-heading">
              <div><span className="admin-eyebrow">CARE NETWORK</span><h2>Hospital management</h2></div>
              <button className="primary-button" onClick={() => setHospitalDraft({})}>Add hospital</button>
            </div>
            {hospitalDraft !== null && (
              <form className="admin-form" onSubmit={submitHospital}>
                <h3>{hospitalDraft.hospital_id ? "Edit hospital" : "New hospital"}</h3>
                <label>Branch code<input name="branch_code" required maxLength="20" defaultValue={hospitalDraft.branch_code || ""} /></label>
                <label>Hospital name<input name="hospital_name" required maxLength="150" defaultValue={hospitalDraft.hospital_name || ""} /></label>
                <label>City<input name="city" required maxLength="100" defaultValue={hospitalDraft.city || ""} /></label>
                <label>Address<input name="address" maxLength="255" defaultValue={hospitalDraft.address || ""} /></label>
                <div className="form-actions"><button className="primary-button" type="submit">Save hospital</button><button className="secondary-button" type="button" onClick={() => setHospitalDraft(null)}>Cancel</button></div>
              </form>
            )}
            <SearchBar value={search} onChange={setSearch} placeholder="Search hospitals by name, city or branch…" />
            <div className="admin-card-grid">
              {filtered(hospitals, "hospital_name", "city", "branch_code").map((hospital) => {
                const associatedDoctors = doctors.filter((doctor) => doctor.hospital_id === hospital.hospital_id);
                const associatedLabs = laboratories.filter((lab) => lab.hospital_id === hospital.hospital_id);
                return (
                  <article className="facility-card" key={hospital.hospital_id}>
                    <div className="facility-card-title"><h3>{hospital.hospital_name}</h3><StatusBadge value={hospital.is_active ? "Active" : "Inactive"} /></div>
                    <p>{hospital.city} · {hospital.branch_code}</p>
                    <small>{hospital.address || "Address not provided"}</small>
                    <div className="association-list"><strong>Doctors ({hospital.doctor_count})</strong><span>{associatedDoctors.map((doctor) => doctor.full_name).join(", ") || "No doctor profiles"}</span></div>
                    <div className="association-list"><strong>Laboratories ({hospital.laboratory_count})</strong><span>{associatedLabs.map((lab) => lab.lab_name).join(", ") || "No laboratories"}</span></div>
                    <div className="card-actions">
                      <button className="secondary-button" onClick={() => setHospitalDraft(hospital)}>Edit</button>
                      <button className={hospital.is_active ? "danger-button" : "primary-button"} onClick={() => toggleHospital(hospital)}>{hospital.is_active ? "Deactivate" : "Activate"}</button>
                    </div>
                  </article>
                );
              })}
              {!hospitals.length && <p className="admin-empty">No hospitals returned.</p>}
            </div>
          </section>
        )}

        {section === "laboratories" && (
          <section className="admin-panel">
            <div className="panel-heading">
              <div><span className="admin-eyebrow">TESTING NETWORK</span><h2>Diagnostic laboratory management</h2></div>
              <button className="primary-button" onClick={() => setLaboratoryDraft({})}>Add laboratory</button>
            </div>
            {laboratoryDraft !== null && (
              <form className="admin-form" onSubmit={submitLaboratory}>
                <h3>{laboratoryDraft.lab_id ? "Edit laboratory" : "New laboratory"}</h3>
                <label>Laboratory code<input name="lab_code" required maxLength="20" defaultValue={laboratoryDraft.lab_code || ""} /></label>
                <label>Laboratory name<input name="lab_name" required maxLength="150" defaultValue={laboratoryDraft.lab_name || ""} /></label>
                <label>City<input name="city" required maxLength="100" defaultValue={laboratoryDraft.city || ""} /></label>
                <label>Hospital<select name="hospital_id" required defaultValue={laboratoryDraft.hospital_id || ""}><option value="" disabled>Select a hospital</option>{activeHospitals.map((hospital) => <option key={hospital.hospital_id} value={hospital.hospital_id}>{hospital.hospital_name}</option>)}</select></label>
                <div className="form-actions"><button className="primary-button" type="submit">Save laboratory</button><button className="secondary-button" type="button" onClick={() => setLaboratoryDraft(null)}>Cancel</button></div>
              </form>
            )}
            <SearchBar value={search} onChange={setSearch} placeholder="Search laboratories by name, city or hospital…" />
            <div className="admin-table-wrapper">
              <table>
                <thead><tr><th>Code</th><th>Laboratory</th><th>City</th><th>Hospital</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                  {filtered(laboratories, "lab_code", "lab_name", "city", "hospital_name").map((lab) => (
                    <tr key={lab.lab_id}>
                      <td>{lab.lab_code}</td><td>{lab.lab_name}</td><td>{lab.city}</td><td>{lab.hospital_name || "Unassigned"}</td>
                      <td><StatusBadge value={lab.is_active && lab.hospital_is_active ? "Active" : "Inactive"} /></td>
                      <td><div className="admin-actions"><button className="secondary-button" onClick={() => setLaboratoryDraft(lab)}>Edit</button><button className={lab.is_active ? "danger-button" : "primary-button"} onClick={() => toggleLaboratory(lab)}>{lab.is_active ? "Deactivate" : "Activate"}</button></div></td>
                    </tr>
                  ))}
                  {!laboratories.length && <TableMessage columns={6}>No laboratories returned.</TableMessage>}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {section === "doctors" && (
          <section className="admin-panel">
            <div className="panel-heading">
              <div><span className="admin-eyebrow">CLINICAL NETWORK</span><h2>Doctor management</h2></div>
              <button className="primary-button" onClick={() => setDoctorDraft({})}>Create doctor account</button>
            </div>
            {doctorDraft !== null && (
              <form className="admin-form" onSubmit={submitDoctor}>
                <h3>{doctorDraft.doctor_id ? "Edit doctor profile" : "Create secure doctor account"}</h3>
                <label>Full name<input name="full_name" required maxLength="100" defaultValue={doctorDraft.full_name || ""} /></label>
                <label>Specialty<input name="specialty" required maxLength="100" defaultValue={doctorDraft.specialty || ""} /></label>
                <label>Hospital<select name="hospital_id" required defaultValue={doctorDraft.hospital_id || ""}><option value="" disabled>Select a hospital</option>{activeHospitals.map((hospital) => <option key={hospital.hospital_id} value={hospital.hospital_id}>{hospital.hospital_name}</option>)}</select></label>
                {!doctorDraft.doctor_id && <><label>Login email<input name="email" type="email" required maxLength="150" /></label><label>Temporary password<input name="password" type="password" minLength="8" maxLength="128" required autoComplete="new-password" /></label><p className="form-note">The doctor role is assigned by this protected admin operation. Public registration remains patient-only.</p></>}
                <div className="form-actions"><button className="primary-button" type="submit">Save doctor</button><button className="secondary-button" type="button" onClick={() => setDoctorDraft(null)}>Cancel</button></div>
              </form>
            )}
            <SearchBar value={search} onChange={setSearch} placeholder="Search doctors by name, specialty, hospital or email…" />
            <div className="admin-table-wrapper">
              <table>
                <thead><tr><th>Doctor</th><th>Specialty</th><th>Hospital</th><th>Login email</th><th>Appointments</th><th>Availability</th><th>Actions</th></tr></thead>
                <tbody>
                  {filtered(doctors, "full_name", "specialty", "hospital_name", "email").map((doctor) => (
                    <tr key={doctor.doctor_id}>
                      <td>{doctor.full_name}</td><td>{doctor.specialty}</td><td>{doctor.hospital_name || "Unassigned"}</td><td>{doctor.email || "Legacy directory profile"}</td><td>{doctor.appointment_count}</td>
                      <td><StatusBadge value={doctor.available_for_booking ? "Active" : "Inactive"} /></td>
                      <td><div className="admin-actions"><button className="secondary-button" onClick={() => setDoctorDraft(doctor)}>Edit</button><button className="secondary-button" onClick={() => viewDoctorAppointments(doctor.doctor_id)}>Appointments</button><button className={doctor.is_active ? "danger-button" : "primary-button"} onClick={() => toggleDoctor(doctor)}>{doctor.is_active ? "Deactivate" : "Activate"}</button></div></td>
                    </tr>
                  ))}
                  {!doctors.length && <TableMessage columns={7}>No doctors returned.</TableMessage>}
                </tbody>
              </table>
            </div>
            {doctorAppointments && (
              <div className="admin-subpanel">
                <div className="panel-heading"><h3>Appointments for doctor #{doctorAppointments.doctorId}</h3><button className="text-button" onClick={() => setDoctorAppointments(null)}>Close</button></div>
                <AppointmentTable appointments={doctorAppointments.appointments} showActions={false} onStatusChange={submitAppointmentStatus} />
              </div>
            )}
          </section>
        )}

        {section === "users" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">ACCOUNT ACCESS</span><h2>User management</h2></div></div>
            <SearchBar value={search} onChange={setSearch} placeholder="Search by name, email or role…" />
            <div className="admin-table-wrapper">
              <table>
                <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Account status</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>
                  {filtered(users, "full_name", "email", "role").map((item) => (
                    <tr key={item.user_id}>
                      <td>{item.user_id}</td><td>{item.full_name}</td><td>{item.email}</td><td className="capitalize">{item.role}</td><td><StatusBadge value={item.account_status} /></td><td>{formatDate(item.created_at, true)}</td>
                      <td>{String(item.user_id) === String(user?.user_id) ? <span className="muted-text">Current account</span> : <div className="admin-actions">
                        {item.account_status === "active"
                          ? <button className="suspend-button" onClick={() => updateUserStatus(item.user_id, "suspended")}>Suspend</button>
                          : item.account_status === "suspended"
                            ? <button className="primary-button" onClick={() => updateUserStatus(item.user_id, "active")}>Reactivate</button>
                            : <button className="primary-button" onClick={() => updateUserStatus(item.user_id, "active")}>Activate</button>}
                        {item.account_status !== "deactivated" && <button className="danger-button" onClick={() => {
                          if (window.confirm("Deactivate this account? Historical records will be preserved.")) {
                            updateUserStatus(item.user_id, "deactivated");
                          }
                        }}>Deactivate</button>}
                      </div>}</td>
                    </tr>
                  ))}
                  {!users.length && <TableMessage columns={7}>No users returned.</TableMessage>}
                </tbody>
              </table>
            </div>
            <p className="form-note">Passwords, password hashes and authentication tokens are never displayed.</p>
          </section>
        )}

        {section === "appointments" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">SCHEDULING</span><h2>Appointment management</h2></div></div>
            <form className="filter-form" onSubmit={filterAppointments}>
              <label>Hospital<select value={appointmentFilters.hospital_id} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, hospital_id: event.target.value })}><option value="">All hospitals</option>{hospitals.map((hospital) => <option key={hospital.hospital_id} value={hospital.hospital_id}>{hospital.hospital_name}</option>)}</select></label>
              <label>Doctor<select value={appointmentFilters.doctor_id} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, doctor_id: event.target.value })}><option value="">All doctors</option>{doctors.map((doctor) => <option key={doctor.doctor_id} value={doctor.doctor_id}>{doctor.full_name}</option>)}</select></label>
              <label>Patient ID<input value={appointmentFilters.patient_id} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, patient_id: event.target.value })} inputMode="numeric" /></label>
              <label>Date<input type="date" value={appointmentFilters.date} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, date: event.target.value })} /></label>
              <label>Status<select value={appointmentFilters.status} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, status: event.target.value })}><option value="">All statuses</option>{["Pending", "Confirmed", "Completed", "Cancelled"].map((status) => <option key={status}>{status}</option>)}</select></label>
              <label>Search<input value={appointmentFilters.q} onChange={(event) => setAppointmentFilters({ ...appointmentFilters, q: event.target.value })} placeholder="Patient, doctor…" /></label>
              <button className="primary-button" type="submit">Apply filters</button>
            </form>
            <AppointmentTable appointments={appointments} showActions onStatusChange={submitAppointmentStatus} />
          </section>
        )}

        {section === "medical-records" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">RESTRICTED OVERSIGHT</span><h2>Medical record metadata</h2></div></div>
            <p className="privacy-note">Clinical diagnoses, treatment details and prescriptions are intentionally not exposed in this admin view. Viewing metadata is recorded in the audit log.</p>
            <SearchBar value={search} onChange={setSearch} placeholder="Search patient, doctor or email…" />
            <div className="admin-table-wrapper"><table>
              <thead><tr><th>Record ID</th><th>Patient</th><th>Doctor</th><th>Specialty</th><th>Hospital</th><th>Record date</th></tr></thead>
              <tbody>
                {filtered(medicalRecords, "patient_name", "patient_email", "doctor_name", "specialty").map((record) => (
                  <tr key={record.record_id}><td>{record.record_id}</td><td>{record.patient_name} <small>{record.patient_email}</small></td><td>{record.doctor_name}</td><td>{record.specialty}</td><td>{record.hospital_name || "—"}</td><td>{formatDate(record.record_date, true)}</td></tr>
                ))}
                {!medicalRecords.length && <TableMessage columns={6}>No medical records returned.</TableMessage>}
              </tbody>
            </table></div>
          </section>
        )}

        {section === "lab-reports" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">DIAGNOSTIC OVERSIGHT</span><h2>Lab report metadata</h2></div></div>
            <p className="privacy-note">Test results and clinical notes are not returned to this administrative view. Metadata access and modifications are audited.</p>
            {reportDraft && (
              <form className="admin-form" onSubmit={submitReport}>
                <h3>Edit report #{reportDraft.report_id}</h3>
                <label>Test name<input name="test_name" required maxLength="150" defaultValue={reportDraft.test_name} /></label>
                <label>Laboratory<select name="lab_id" required defaultValue={reportDraft.lab_id || ""}><option value="" disabled>Select a laboratory</option>{laboratories.filter((lab) => lab.is_active && lab.hospital_is_active).map((lab) => <option key={lab.lab_id} value={lab.lab_id}>{lab.lab_name} — {lab.hospital_name}</option>)}</select></label>
                <label>Report date<input name="report_date" type="date" required defaultValue={String(reportDraft.report_date || "").slice(0, 10)} /></label>
                <div className="form-actions"><button className="primary-button" type="submit">Save metadata</button><button className="secondary-button" type="button" onClick={() => setReportDraft(null)}>Cancel</button></div>
              </form>
            )}
            <SearchBar value={search} onChange={setSearch} placeholder="Search report, patient, doctor or laboratory…" />
            <div className="admin-table-wrapper"><table>
              <thead><tr><th>Report</th><th>Patient</th><th>Doctor</th><th>Test</th><th>Laboratory</th><th>Hospital</th><th>Report date</th><th>Action</th></tr></thead>
              <tbody>
                {filtered(labReports, "test_name", "patient_name", "patient_email", "doctor_name", "lab_name").map((report) => (
                  <tr key={report.report_id}><td>{report.report_id}</td><td>{report.patient_name}</td><td>{report.doctor_name}</td><td>{report.test_name}</td><td>{report.lab_name || "—"}</td><td>{report.hospital_name || "—"}</td><td>{formatDate(report.report_date, true)}</td><td><button className="secondary-button" onClick={() => setReportDraft(report)}>Edit metadata</button></td></tr>
                ))}
                {!labReports.length && <TableMessage columns={8}>No lab reports returned.</TableMessage>}
              </tbody>
            </table></div>
          </section>
        )}

        {section === "payments" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">SIMULATED TRANSACTIONS</span><h2>Payment management</h2></div><span className="simulation-label">SIMULATION ONLY</span></div>
            <p className="privacy-note">Payments are simulated. This page is read-only; administrators cannot mark payments successful or change payment status.</p>
            <SearchBar value={search} onChange={setSearch} placeholder="Search patient, appointment or transaction reference…" />
            <div className="admin-table-wrapper"><table>
              <thead><tr><th>Reference</th><th>Appointment</th><th>Patient</th><th>Doctor / hospital</th><th>Amount</th><th>Status</th><th>Created</th></tr></thead>
              <tbody>
                {filtered(payments, "transaction_reference", "appointment_id", "patient_name", "patient_email", "doctor_name", "hospital_name", "status").map((payment) => (
                  <tr key={payment.payment_id}><td>{payment.transaction_reference}</td><td>#{payment.appointment_id}<small>{formatDate(payment.appointment_date)}</small></td><td>{payment.patient_name}</td><td>{payment.doctor_name}<small>{payment.hospital_name || "—"}</small></td><td>{payment.amount} {payment.currency}</td><td><StatusBadge value={payment.status} /></td><td>{formatDate(payment.created_at)}</td></tr>
                ))}
                {!payments.length && <TableMessage columns={7}>No payments returned.</TableMessage>}
              </tbody>
            </table></div>
          </section>
        )}

        {section === "audit-logs" && (
          <section className="admin-panel">
            <div className="panel-heading"><div><span className="admin-eyebrow">SECURITY MONITORING</span><h2>Read-only audit log</h2></div></div>
            <p className="privacy-note">Audit events are available for review only. The dashboard does not provide edit or delete controls.</p>
            <SearchBar value={search} onChange={setSearch} placeholder="Search actor, action, resource or details…" />
            <div className="admin-table-wrapper"><table>
              <thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>Event details</th><th>IP address</th><th>Date and time</th></tr></thead>
              <tbody>
                {filtered(auditLogs, "actor_name", "action", "target_type", "target_id", "event_details", "ip_address").map((entry) => (
                  <tr key={entry.log_id}><td>{entry.actor_name || "System"}<small>ID {entry.actor_user_id || "—"}</small></td><td>{entry.action}</td><td>{entry.target_type || "—"}{entry.target_id ? ` #${entry.target_id}` : ""}</td><td>{entry.event_details || "—"}</td><td>{entry.ip_address || "—"}</td><td>{formatDate(entry.created_at)}</td></tr>
                ))}
                {!auditLogs.length && <TableMessage columns={6}>No audit events returned.</TableMessage>}
              </tbody>
            </table></div>
          </section>
        )}
      </main>
    </div>
  );
}

function SearchBar({ value, onChange, placeholder }) {
  return (
    <label className="admin-search">
      <span className="sr-only">Search</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
    </label>
  );
}

function AppointmentTable({ appointments, showActions, onStatusChange }) {
  return (
    <div className="admin-table-wrapper">
      <table>
        <thead><tr><th>Appointment</th><th>Patient</th><th>Doctor</th><th>Hospital</th><th>Date</th><th>Reason</th><th>Status</th>{showActions && <th>Update status</th>}</tr></thead>
        <tbody>
          {appointments.map((appointment) => {
            const transitions = {
              Pending: ["Confirmed", "Cancelled"],
              Confirmed: ["Completed", "Cancelled"],
              Completed: [],
              Cancelled: [],
            };
            const nextStatuses = transitions[appointment.status] || [];
            return (
              <tr key={appointment.appointment_id}>
                <td>#{appointment.appointment_id}</td>
                <td>{appointment.patient_name || `#${appointment.patient_id}`}<small>{appointment.patient_email}</small></td>
                <td>{appointment.doctor_name}</td><td>{appointment.hospital_name || "—"}</td>
                <td>{formatDate(appointment.appointment_date)}</td><td>{appointment.reason}</td><td><StatusBadge value={appointment.status} /></td>
                {showActions && <td><select aria-label={`Update appointment ${appointment.appointment_id} status`} value="" disabled={!nextStatuses.length} onChange={(event) => onStatusChange(appointment.appointment_id, event.target.value)}><option value="">{nextStatuses.length ? "Select status" : "Final"}</option>{nextStatuses.map((status) => <option key={status} value={status}>{status}</option>)}</select></td>}
              </tr>
            );
          })}
          {!appointments.length && <TableMessage columns={showActions ? 8 : 7}>No appointments match the current view.</TableMessage>}
        </tbody>
      </table>
    </div>
  );
}

export default AdminDashboard;
