
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Dashboard.css";

const API = `${import.meta.env.VITE_API_URL}/api`;

const apiFetch = (path, options = {}) => fetch(`${API}${path}`, {
  ...options,
  credentials: "include",
});

function formatDate(value, includeTime = false) {
  if (!value) return "Not available";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString("en-PK", includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }
  );
}

function formatCurrency(value, currency) {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return `${currency} ${value}`;

  return `${currency} ${amount.toLocaleString("en-PK", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

function PatientDashboard() {
  const navigate = useNavigate();

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const [hospitals, setHospitals] = useState([]);
  const [hospitalsLoading, setHospitalsLoading] = useState(true);
  const [hospitalsError, setHospitalsError] = useState("");

  const [doctors, setDoctors] = useState([]);
  const [doctorsLoading, setDoctorsLoading] = useState(true);
  const [doctorsError, setDoctorsError] = useState("");
  const [doctorHospitalFilter, setDoctorHospitalFilter] = useState("");
  const [specialtyFilter, setSpecialtyFilter] = useState("");
  const [selectedHospital, setSelectedHospital] = useState("");

  const [selectedDoctor, setSelectedDoctor] = useState("");
  const [appointmentDate, setAppointmentDate] = useState("");
  const [reason, setReason] = useState("");
  const [bookingLoading, setBookingLoading] = useState(false);
  const [bookingMessage, setBookingMessage] = useState("");
  const [bookingError, setBookingError] = useState("");
  const [bookedAppointmentId, setBookedAppointmentId] = useState(null);

  const [paymentOptions, setPaymentOptions] = useState(null);
  const [paymentOptionsLoading, setPaymentOptionsLoading] = useState(true);
  const [paymentOptionsError, setPaymentOptionsError] = useState("");
  const [payments, setPayments] = useState([]);
  const [paymentsLoading, setPaymentsLoading] = useState(true);
  const [paymentsError, setPaymentsError] = useState("");
  const [paymentActionId, setPaymentActionId] = useState(null);
  const [paymentNotice, setPaymentNotice] = useState("");

  const [myAppointments, setMyAppointments] = useState([]);
  const [appointmentsLoading, setAppointmentsLoading] = useState(true);
  const [appointmentsError, setAppointmentsError] = useState("");

  const [medicalRecords, setMedicalRecords] = useState([]);
  const [recordsLoading, setRecordsLoading] = useState(true);
  const [recordsError, setRecordsError] = useState("");

  const [labReports, setLabReports] = useState([]);
  const [labReportsLoading, setLabReportsLoading] = useState(true);
  const [labReportsError, setLabReportsError] = useState("");
  const [laboratories, setLaboratories] = useState([]);
  const [laboratoriesLoading, setLaboratoriesLoading] = useState(true);
  const [laboratoriesError, setLaboratoriesError] = useState("");

  const logoutLocally = useCallback(() => {
    sessionStorage.removeItem("user");
    navigate("/login");
  }, [navigate]);

  const loadPaymentOptions = useCallback(async () => {
    const response = await apiFetch("/patient/payment-config");

    if (response.status === 401 || response.status === 403) {
      logoutLocally();
      return null;
    }

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || "Unable to load payment information.");
    }

    return data;
  }, [logoutLocally]);

  const refreshPayments = useCallback(async () => {
    const response = await apiFetch("/patient/payments");

    if (response.status === 401 || response.status === 403) {
      logoutLocally();
      return null;
    }

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || "Unable to load payment history.");
    }

    return Array.isArray(data.payments) ? data.payments : [];
  }, [logoutLocally]);

  // Verify the saved patient session.
  useEffect(() => {
    const savedUser = sessionStorage.getItem("user");

    if (!savedUser) {
      logoutLocally();
      return;
    }

    try {
      const parsedUser = JSON.parse(savedUser);

      if (parsedUser.role !== "patient") {
        logoutLocally();
        return;
      }

      apiFetch("/patient/profile")
        .then(async (response) => {
          if (response.status === 401 || response.status === 403) {
            logoutLocally();
            return;
          }

          if (!response.ok) {
            throw new Error("Unable to verify your profile.");
          }

          const data = await response.json();
          if (!data.profile) {
            throw new Error("Patient profile is unavailable.");
          }
          setUser(data.profile);
        })
        .catch(() => setUser(parsedUser))
        .finally(() => setLoading(false));
    } catch {
      logoutLocally();
    }
  }, [logoutLocally]);

  // Load active hospitals from the public directory endpoint.
  useEffect(() => {
    if (!user) return;

    apiFetch("/hospitals")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.message || "Unable to load hospitals.");
        }
        setHospitals(Array.isArray(data.hospitals) ? data.hospitals : []);
      })
      .catch((error) => {
        setHospitalsError(error.message || "Unable to load hospitals.");
      })
      .finally(() => setHospitalsLoading(false));
  }, [user]);

  // Load available doctors.
  useEffect(() => {
    if (!user) return;

    apiFetch("/doctors")
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load doctors.");
        const data = await response.json();
        setDoctors(data.doctors || []);
      })
      .catch(() => setDoctorsError("Unable to load doctors. Please try again."))
      .finally(() => setDoctorsLoading(false));
  }, [user]);

  // Load active diagnostic laboratories from the public directory endpoint.
  useEffect(() => {
    if (!user) return;

    apiFetch("/laboratories")
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.message || "Unable to load laboratories.");
        }
        setLaboratories(
          Array.isArray(data.laboratories) ? data.laboratories : []
        );
      })
      .catch((error) => {
        setLaboratoriesError(error.message || "Unable to load laboratories.");
      })
      .finally(() => setLaboratoriesLoading(false));
  }, [user]);

  // Load the patient's appointments.
  useEffect(() => {
    if (!user) return;

    apiFetch("/patient/appointments")
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          logoutLocally();
          return;
        }
        if (!response.ok) throw new Error("Unable to load appointments.");
        const data = await response.json();
        setMyAppointments(data.appointments || []);
      })
      .catch(() => setAppointmentsError("Unable to load your appointments."))
      .finally(() => setAppointmentsLoading(false));
  }, [user, logoutLocally]);

  // Load the patient's medical records.
  useEffect(() => {
    if (!user) return;

    apiFetch("/patient/medical-records")
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          logoutLocally();
          return;
        }
        if (!response.ok) throw new Error("Unable to load medical records.");
        const data = await response.json();
        setMedicalRecords(data.medical_records || []);
      })
      .catch(() => setRecordsError("Unable to load your medical records."))
      .finally(() => setRecordsLoading(false));
  }, [user, logoutLocally]);

  // Load the patient's lab reports.
  useEffect(() => {
    if (!user) return;

    apiFetch("/patient/lab-reports")
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          logoutLocally();
          return;
        }
        if (!response.ok) throw new Error("Unable to load lab reports.");
        const data = await response.json();
        setLabReports(data.lab_reports || []);
      })
      .catch(() => setLabReportsError("Unable to load your lab reports."))
      .finally(() => setLabReportsLoading(false));
  }, [user, logoutLocally]);

  useEffect(() => {
    if (!user) return;

    loadPaymentOptions()
      .then((options) => {
        if (!options) return;
        setPaymentOptions(options);
        setPaymentOptionsError("");
      })
      .catch((error) => {
        setPaymentOptionsError(error.message || "Unable to load payment information.");
      })
      .finally(() => setPaymentOptionsLoading(false));

    refreshPayments()
      .then((paymentHistory) => {
        if (!paymentHistory) return;
        setPayments(paymentHistory);
        setPaymentsError("");
      })
      .catch((error) => {
        setPaymentsError(error.message || "Unable to load payment history.");
      })
      .finally(() => setPaymentsLoading(false));
  }, [user, loadPaymentOptions, refreshPayments]);

  const upcomingAppointments = useMemo(() => {
    const now = new Date();

    return myAppointments.filter((appointment) => {
      const date = new Date(appointment.appointment_date);
      return (
        date >= now &&
        ["Pending", "Confirmed"].includes(appointment.status)
      );
    });
  }, [myAppointments]);

  const previousAppointments = useMemo(() => {
    const now = new Date();

    return myAppointments.filter((appointment) => {
      const date = new Date(appointment.appointment_date);
      return (
        date < now ||
        ["Completed", "Cancelled"].includes(appointment.status)
      );
    });
  }, [myAppointments]);

  const filteredDoctors = useMemo(
    () => doctors.filter((doctor) => (
      (!doctorHospitalFilter ||
        String(doctor.hospital_id) === doctorHospitalFilter) &&
      (!specialtyFilter || doctor.specialty === specialtyFilter)
    )),
    [doctors, doctorHospitalFilter, specialtyFilter]
  );

  const appointmentDoctors = useMemo(
    () => doctors.filter(
      (doctor) => String(doctor.hospital_id) === selectedHospital
    ),
    [doctors, selectedHospital]
  );

  const specialties = useMemo(
    () => [...new Set(doctors.map((doctor) => doctor.specialty).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right)),
    [doctors]
  );

  const appointmentGroups = [
    { key: "upcoming", title: "Upcoming", appointments: upcomingAppointments },
    { key: "previous", title: "Previous", appointments: previousAppointments },
  ];

  const refreshAppointments = async () => {
    const response = await apiFetch("/patient/appointments");

    if (response.status === 401 || response.status === 403) {
      logoutLocally();
      return;
    }

    if (!response.ok) throw new Error("Unable to refresh appointments.");

    const data = await response.json();
    setMyAppointments(data.appointments || []);
    setAppointmentsError("");
  };

  const handleBookAppointment = async (event) => {
    event.preventDefault();
    setBookingMessage("");
    setBookingError("");
    setBookedAppointmentId(null);

    try {
      setBookingLoading(true);

      const response = await apiFetch("/appointments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          hospital_id: selectedHospital,
          doctor_id: selectedDoctor,
          appointment_date: appointmentDate,
          reason,
        }),
      });

      const data = await response.json();

      if (response.status === 401 || response.status === 403) {
        logoutLocally();
        return;
      }

      if (!response.ok) {
        throw new Error(data.message || "Unable to book appointment.");
      }

      setBookingMessage(data.message || "Appointment booked successfully.");
      setBookedAppointmentId(data.appointment_id);
      setSelectedDoctor("");
      setAppointmentDate("");
      setReason("");

      await refreshAppointments().catch((error) => {
        setAppointmentsError(
          error.message || "Unable to refresh appointments."
        );
      });
      const paymentHistory = await refreshPayments().catch((error) => {
        setPaymentsError(error.message || "Unable to load payment history.");
        return null;
      });
      if (paymentHistory) {
        setPayments(paymentHistory);
        setPaymentsError("");
      }
      setBookingMessage(
        `Appointment #${data.appointment_id} booked. Payment is pending; complete the simulation in My Payments.`
      );
    } catch (error) {
      setBookingError(error.message || "Something went wrong.");
    } finally {
      setBookingLoading(false);
    }
  };

  const handlePaymentSimulation = async (paymentId) => {
    setPaymentActionId(paymentId);
    setPaymentNotice("");

    try {
      const response = await apiFetch(
        `/patient/payments/${paymentId}/simulate`,
        {
          method: "POST",
        }
      );
      const data = await response.json();

      if (response.status === 401 || response.status === 403) {
        logoutLocally();
        return;
      }

      if (!response.ok) {
        throw new Error(data.message || "Unable to simulate payment.");
      }

      const paymentHistory = await refreshPayments();
      if (paymentHistory) {
        setPayments(paymentHistory);
        setPaymentsError("");
      }
      setPaymentNotice(
        data.payment.status === "Successful"
          ? `Simulation successful for appointment #${data.payment.appointment_id}. No real payment was charged.`
          : `Simulation failed for appointment #${data.payment.appointment_id}. No real payment was charged.`
      );
    } catch (error) {
      setPaymentNotice(error.message || "Unable to simulate payment.");
    } finally {
      setPaymentActionId(null);
    }
  };

  const handleCancelAppointment = async (appointmentId) => {
    const confirmed = window.confirm(
      "Are you sure you want to cancel this appointment?"
    );

    if (!confirmed) return;

    try {
      const response = await apiFetch(
        `/patient/appointments/${appointmentId}/cancel`,
        {
          method: "PATCH",
        }
      );

      const data = await response.json();

      if (response.status === 401 || response.status === 403) {
        logoutLocally();
        return;
      }

      if (!response.ok) {
        throw new Error(data.message || "Unable to cancel appointment.");
      }

      await refreshAppointments();
      window.alert("Appointment cancelled successfully.");
    } catch (error) {
      window.alert(error.message || "Could not connect to the server.");
    }
  };

  const handleLogout = async () => {
    try {
      const response = await apiFetch("/logout", {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error("Secure logout failed. Please try again.");
      }

      logoutLocally();
    } catch (error) {
      window.alert(error.message || "Unable to complete secure logout.");
    }
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner" />
        <p>Loading your MediLink dashboard...</p>
      </div>
    );
  }

  if (!user) return null;

  const firstName = user.full_name?.trim().split(" ")[0] || "Patient";
  const initial = user.full_name?.trim().charAt(0).toUpperCase() || "P";

  const minimumDate = new Date(
    Date.now() - new Date().getTimezoneOffset() * 60000
  ).toISOString().slice(0, 16);

  return (
    <div className="dashboard-page">
      <header className="dashboard-navbar">
        <a href="#overview" className="dashboard-brand">
          <span className="brand-symbol">M</span>
          <span>
            <strong>MediLink Health</strong>
            <small>Patient Portal</small>
          </span>
        </a>

        <nav className="dashboard-nav">
          <a href="#overview">Dashboard</a>
          <a href="#hospitals">Hospitals</a>
          <a href="#doctors">Find Doctors</a>
          <a href="#book-appointment">Book Visit</a>
          <a href="#appointment-history">My Appointments</a>
          <a href="#laboratories">Diagnostic Labs</a>
          <a href="#medical-records">Medical Records</a>
          <a href="#lab-reports">Lab Reports</a>
          <a href="#payment-history">Payments</a>
          <a href="#profile">My Profile</a>
        </nav>

        <div className="dashboard-nav-actions">
          <div className="navbar-avatar">{initial}</div>
          <button onClick={handleLogout} className="logout-button">
            Log Out
          </button>
        </div>
      </header>

      <main className="dashboard-main" id="overview">
        <section className="dashboard-heading">
          <div>
            <span className="eyebrow">DASHBOARD OVERVIEW</span>
            <h1>Welcome, {firstName}!</h1>
            <p>Here's an overview of your healthcare activity.</p>
          </div>
          <a href="#book-appointment" className="dashboard-primary-button">
            + Book an Appointment
          </a>
        </section>

        <section className="dashboard-welcome">
          <div className="welcome-content">
            <span className="welcome-tag">YOUR HEALTH, OUR PRIORITY</span>
            <h2>Your health journey starts here.</h2>
            <p>
              Find qualified doctors, manage your appointments, and stay
              connected with your healthcare through one secure platform.
            </p>
            <a href="#hospitals" className="welcome-button">
              Find a Hospital <span>→</span>
            </a>
          </div>
          <div className="welcome-decoration" aria-hidden="true">
            <span className="welcome-cross">+</span>
            <span className="welcome-circle">✚</span>
            <span className="welcome-small-circle" />
          </div>
        </section>

        <section className="dashboard-summary">
          <article className="summary-card">
            <div className="summary-icon teal-icon">🏥</div>
            <div>
              <p>Active Hospitals</p>
              <strong>
                {hospitalsLoading ? "—" : hospitals.length}
              </strong>
              <span>Care locations</span>
            </div>
          </article>

          <article className="summary-card">
            <div className="summary-icon orange-icon">🩺</div>
            <div>
              <p>Available Doctors</p>
              <strong>{doctorsLoading ? "—" : doctors.length}</strong>
              <span>Healthcare specialists</span>
            </div>
          </article>

          <article className="summary-card">
            <div className="summary-icon blue-icon">📋</div>
            <div>
              <p>Medical Records</p>
              <strong>{recordsLoading ? "—" : medicalRecords.length}</strong>
              <span>Your health history</span>
            </div>
          </article>

          <article className="summary-card">
            <div className="summary-icon purple-icon">🧪</div>
            <div>
              <p>Lab Reports</p>
              <strong>{labReportsLoading ? "—" : labReports.length}</strong>
              <span>Your test results</span>
            </div>
          </article>
        </section>

        <section className="dashboard-section" id="hospitals">
          <div className="section-heading">
            <div>
              <span className="eyebrow">OUR CARE NETWORK</span>
              <h2>Find a Hospital</h2>
              <p>Browse active MediLink locations and choose where to receive care.</p>
            </div>
          </div>

          {hospitalsError && (
            <p className="section-message error-text">{hospitalsError}</p>
          )}
          {hospitalsLoading && (
            <p className="section-message">Loading hospitals...</p>
          )}
          {!hospitalsLoading && !hospitalsError && hospitals.length === 0 && (
            <p className="section-message">No active hospitals are available.</p>
          )}

          <div className="facility-grid">
            {!hospitalsLoading && hospitals.map((hospital) => (
              <article className="facility-card" key={hospital.hospital_id}>
                <div className="facility-card-heading">
                  <span className="facility-icon" aria-hidden="true">+</span>
                  <span className="facility-status">
                    {hospital.is_active ? "Active" : "Inactive"}
                  </span>
                </div>
                <h3>{hospital.hospital_name}</h3>
                <p className="facility-city">{hospital.city}</p>
                <p className="facility-address">{hospital.address}</p>
                <a
                  href="#book-appointment"
                  className="facility-link"
                  onClick={() => {
                    setSelectedHospital(String(hospital.hospital_id));
                    setSelectedDoctor("");
                  }}
                >
                  Book at this hospital <span>→</span>
                </a>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section" id="doctors">
          <div className="section-heading">
            <div>
              <span className="eyebrow">OUR SPECIALISTS</span>
              <h2>Find a Doctor</h2>
              <p>Filter active doctors by hospital or specialty.</p>
            </div>
            <a href="#book-appointment" className="text-link">Book a visit →</a>
          </div>

          {doctorsLoading && <p className="section-message">Loading doctors...</p>}
          {doctorsError && <p className="section-message error-text">{doctorsError}</p>}

          <div className="directory-filters">
            <div className="form-field">
              <label htmlFor="doctor-hospital-filter">Hospital</label>
              <select
                id="doctor-hospital-filter"
                value={doctorHospitalFilter}
                onChange={(event) => setDoctorHospitalFilter(event.target.value)}
              >
                <option value="">All active hospitals</option>
                {hospitals.map((hospital) => (
                  <option
                    key={hospital.hospital_id}
                    value={hospital.hospital_id}
                  >
                    {hospital.hospital_name}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="doctor-specialty-filter">Specialty</label>
              <select
                id="doctor-specialty-filter"
                value={specialtyFilter}
                onChange={(event) => setSpecialtyFilter(event.target.value)}
              >
                <option value="">All specialties</option>
                {specialties.map((specialty) => (
                  <option key={specialty} value={specialty}>
                    {specialty}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {!doctorsLoading && !doctorsError && doctors.length === 0 && (
            <p className="section-message">No active doctors are currently available.</p>
          )}
          {!doctorsLoading && !doctorsError && doctors.length > 0 &&
            filteredDoctors.length === 0 && (
              <p className="section-message">
                No active doctors match these filters.
              </p>
            )}

          <div className="doctor-list">
            {filteredDoctors.map((doctor) => (
              <article className="doctor-card" key={doctor.doctor_id}>
                <div className="doctor-avatar">🩺</div>
                <div className="doctor-details">
                  <h3>{doctor.full_name}</h3>
                  <p>{doctor.specialty}</p>
                  <small>
                    {doctor.hospital_name}
                    {doctor.hospital_city ? ` · ${doctor.hospital_city}` : ""}
                  </small>
                </div>
                <span className="facility-status">
                  {doctor.is_active ? "Active" : "Inactive"}
                </span>
                <a
                  href="#book-appointment"
                  className="doctor-book-link"
                  onClick={() => {
                    setSelectedHospital(String(doctor.hospital_id));
                    setSelectedDoctor(String(doctor.doctor_id));
                  }}
                >
                  Book
                </a>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section" id="laboratories">
          <div className="section-heading">
            <div>
              <span className="eyebrow">DIAGNOSTIC SERVICES</span>
              <h2>Diagnostic Laboratories</h2>
              <p>Explore active laboratories across the hospital network.</p>
            </div>
            <span className="directory-count">
              {laboratoriesLoading
                ? "Loading..."
                : `${laboratories.length} available`}
            </span>
          </div>

          {laboratoriesError && (
            <p className="section-message error-text">{laboratoriesError}</p>
          )}
          {laboratoriesLoading && (
            <p className="section-message">Loading laboratories...</p>
          )}
          {!laboratoriesLoading && !laboratoriesError &&
            laboratories.length === 0 && (
              <p className="section-message">
                No active diagnostic laboratories are available.
              </p>
            )}

          <div className="facility-grid">
            {!laboratoriesLoading && laboratories.map((laboratory) => (
              <article className="facility-card laboratory-card" key={laboratory.lab_id}>
                <div className="facility-card-heading">
                  <span className="facility-icon lab-icon" aria-hidden="true">+</span>
                  <span className="facility-status">
                    {laboratory.is_active ? "Active" : "Inactive"}
                  </span>
                </div>
                <h3>{laboratory.lab_name}</h3>
                <p className="facility-city">{laboratory.city}</p>
                <p className="facility-address">
                  {laboratory.hospital_name || "Hospital not listed"}
                </p>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section booking-section" id="book-appointment">
          <div className="section-heading">
            <div>
              <span className="eyebrow">SCHEDULE YOUR VISIT</span>
              <h2>Book an Appointment</h2>
              <p>Choose a doctor and provide your appointment details.</p>
            </div>
          </div>

          <form className="appointment-form" onSubmit={handleBookAppointment}>
            <div className="form-field">
              <label htmlFor="appointment-hospital">Select Hospital</label>
              <select
                id="appointment-hospital"
                value={selectedHospital}
                onChange={(event) => {
                  setSelectedHospital(event.target.value);
                  setSelectedDoctor("");
                }}
                required
              >
                <option value="">Choose a hospital</option>
                {hospitals.map((hospital) => (
                  <option
                    key={hospital.hospital_id}
                    value={hospital.hospital_id}
                  >
                    {hospital.hospital_name} - {hospital.city}
                  </option>
                ))}
              </select>
            </div>

            <div className="form-field">
              <label htmlFor="doctor">Select Doctor</label>
              <select
                id="doctor"
                value={selectedDoctor}
                onChange={(event) => setSelectedDoctor(event.target.value)}
                disabled={!selectedHospital || appointmentDoctors.length === 0}
                required
              >
                <option value="">
                  {selectedHospital
                    ? "Choose an active doctor"
                    : "Choose a hospital first"}
                </option>
                {appointmentDoctors.map((doctor) => (
                  <option key={doctor.doctor_id} value={doctor.doctor_id}>
                    {doctor.full_name} - {doctor.specialty}
                  </option>
                ))}
              </select>
              {selectedHospital && appointmentDoctors.length === 0 && (
                <small className="field-hint">
                  No active doctors are available at this hospital.
                </small>
              )}
            </div>

            <div className="form-field">
              <label htmlFor="appointment-date">Appointment Date & Time</label>
              <input
                id="appointment-date"
                type="datetime-local"
                value={appointmentDate}
                onChange={(event) => setAppointmentDate(event.target.value)}
                min={minimumDate}
                required
              />
            </div>

            <div className="form-field full-field">
              <label htmlFor="reason">Reason for Appointment</label>
              <textarea
                id="reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Briefly describe why you need an appointment"
                rows="4"
                maxLength="255"
                required
              />
            </div>

            <div className="payment-quote full-field">
              <div>
                <strong>Appointment fee</strong>
                <small>
                  {paymentOptions?.notice ||
                    "Payment is handled in a clearly labelled simulation."}
                </small>
              </div>
              <strong>
                {paymentOptionsLoading
                  ? "Loading fee..."
                  : paymentOptions
                    ? formatCurrency(
                        paymentOptions.appointment_fee,
                        paymentOptions.currency
                      )
                    : "Fee unavailable"}
              </strong>
            </div>
            {paymentOptionsError && (
              <p className="booking-error">{paymentOptionsError}</p>
            )}

            <div className="form-submit-row">
              <button
                type="submit"
                disabled={
                  bookingLoading ||
                  doctors.length === 0 ||
                  !selectedHospital ||
                  paymentOptionsLoading ||
                  !paymentOptions
                }
              >
                {bookingLoading ? "Booking..." : "Confirm Appointment"}
              </button>
            </div>

            {bookingMessage && (
              <p className="booking-success">
                {bookingMessage}
                {bookedAppointmentId && (
                  <> Appointment ID: <strong>{bookedAppointmentId}</strong></>
                )}
              </p>
            )}
            {bookingError && <p className="booking-error">{bookingError}</p>}
          </form>
        </section>

        <section className="dashboard-section" id="appointment-history">
          <div className="section-heading">
            <div>
              <span className="eyebrow">YOUR VISITS</span>
              <h2>My Appointment History</h2>
              <p>Review and manage your scheduled appointments.</p>
            </div>
          </div>

          {appointmentsLoading && <p className="section-message">Loading appointments...</p>}
          {appointmentsError && <p className="section-message error-text">{appointmentsError}</p>}
          {!appointmentsLoading && !appointmentsError && myAppointments.length === 0 && (
            <div className="empty-state">
              <span>📅</span>
              <p>You haven't booked any appointments yet.</p>
              <a href="#book-appointment">Book an appointment →</a>
            </div>
          )}

          {!appointmentsLoading && myAppointments.length > 0 && (
            <div className="appointment-groups">
              {appointmentGroups.map((group) => (
                <section className="appointment-group" key={group.key}>
                  <h3 className="appointment-group-heading">
                    {group.title}
                    <span>{group.appointments.length}</span>
                  </h3>
                  {group.appointments.length === 0 ? (
                    <p className="section-message">
                      No {group.title.toLowerCase()} appointments.
                    </p>
                  ) : (
                    <div className="record-list">
                      {group.appointments.map((appointment) => (
                        <article
                          className="record-card"
                          key={appointment.appointment_id}
                        >
                          <div className="record-card-top">
                            <div>
                              <span className="record-label">
                                APPOINTMENT #{appointment.appointment_id}
                              </span>
                              <h3>{appointment.doctor_name}</h3>
                              <p>{appointment.doctor_specialty}</p>
                            </div>
                            <span
                              className={`status-pill status-${appointment.status?.toLowerCase()}`}
                            >
                              {appointment.status}
                            </span>
                          </div>
                          <div className="record-details-grid">
                            <p>
                              <strong>Hospital</strong>
                              <span>
                                {appointment.hospital_name || "Not available"}
                                {appointment.hospital_city
                                  ? ` · ${appointment.hospital_city}`
                                  : ""}
                              </span>
                            </p>
                            <p>
                              <strong>Date & Time</strong>
                              <span>
                                {formatDate(appointment.appointment_date, true)}
                              </span>
                            </p>
                            <p>
                              <strong>Reason</strong>
                              <span>{appointment.reason || "Not provided"}</span>
                            </p>
                          </div>
                          {(appointment.status === "Pending" ||
                            appointment.status === "Confirmed") && (
                            <button
                              className="cancel-appointment-btn"
                              onClick={() => handleCancelAppointment(
                                appointment.appointment_id
                              )}
                            >
                              Cancel Appointment
                            </button>
                          )}
                        </article>
                      ))}
                    </div>
                  )}
                </section>
              ))}
            </div>
          )}
        </section>

        <section className="dashboard-section" id="payment-history">
          <div className="section-heading">
            <div>
              <span className="eyebrow">PAYMENT ACTIVITY</span>
              <h2>Payment History</h2>
              <p>
                Review appointment payments. This environment simulates
                payments and does not charge you.
              </p>
            </div>
          </div>

          {paymentNotice && (
            <p className="payment-notice" role="status">{paymentNotice}</p>
          )}
          {paymentsLoading && (
            <p className="section-message">Loading payment history...</p>
          )}
          {paymentsError && (
            <p className="section-message error-text">{paymentsError}</p>
          )}
          {!paymentsLoading && !paymentsError && payments.length === 0 && (
            <div className="empty-state">
              <span>💳</span>
              <p>No appointment payments yet.</p>
            </div>
          )}

          <div className="record-list">
            {!paymentsLoading && payments.map((payment) => (
              <article className="record-card payment-record" key={payment.payment_id}>
                <div className="record-card-top">
                  <div>
                    <span className="record-label">
                      APPOINTMENT #{payment.appointment_id}
                    </span>
                    <h3>{payment.doctor_name}</h3>
                    <p>
                      {payment.doctor_specialty} ·{" "}
                      {formatDate(payment.appointment_date, true)}
                    </p>
                  </div>
                  <span
                    className={`payment-status payment-status-${payment.status.toLowerCase()}`}
                  >
                    {payment.status}
                  </span>
                </div>

                <div className="payment-record-footer">
                  <div>
                    <strong>{formatCurrency(payment.amount, payment.currency)}</strong>
                    <small>
                      Simulation ref: SIM-{payment.payment_id}
                    </small>
                    <small>
                      {formatDate(payment.created_at)} · Simulation only
                    </small>
                  </div>
                  {payment.status !== "Successful" && (
                    <button
                      className="payment-action-button"
                      onClick={() => handlePaymentSimulation(payment.payment_id)}
                      disabled={paymentActionId === payment.payment_id}
                    >
                      {paymentActionId === payment.payment_id
                        ? "Processing..."
                        : payment.status === "Failed"
                          ? "Retry simulation"
                          : "Simulate payment"}
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section" id="medical-records">
          <div className="section-heading">
            <div>
              <span className="eyebrow">YOUR HEALTH HISTORY</span>
              <h2>My Medical Records</h2>
              <p>Review your medical history and treatment information.</p>
            </div>
          </div>

          {recordsLoading && <p className="section-message">Loading medical records...</p>}
          {recordsError && <p className="section-message error-text">{recordsError}</p>}
          {!recordsLoading && !recordsError && medicalRecords.length === 0 && (
            <div className="empty-state">
              <span>📋</span>
              <p>No medical records are available yet.</p>
            </div>
          )}

          <div className="record-list">
            {!recordsLoading && medicalRecords.map((record) => (
              <article className="record-card" key={record.record_id}>
                <div className="record-card-top">
                  <div>
                    <span className="record-label">MEDICAL RECORD #{record.record_id}</span>
                    <h3>{record.diagnosis || "Medical Record"}</h3>
                    <p>{record.doctor_name} {record.doctor_specialty ? `· ${record.doctor_specialty}` : ""}</p>
                  </div>
                  <span className="record-date">{formatDate(record.record_date)}</span>
                </div>
                <div className="record-details-grid">
                  <p><strong>Treatment</strong><span>{record.treatment || "Not provided"}</span></p>
                  <p><strong>Prescription</strong><span>{record.prescription || "Not provided"}</span></p>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section" id="lab-reports">
          <div className="section-heading">
            <div>
              <span className="eyebrow">TEST RESULTS</span>
              <h2>My Lab Reports</h2>
              <p>View your laboratory test results and reports.</p>
            </div>
          </div>

          {labReportsLoading && <p className="section-message">Loading lab reports...</p>}
          {labReportsError && <p className="section-message error-text">{labReportsError}</p>}
          {!labReportsLoading && !labReportsError && labReports.length === 0 && (
            <div className="empty-state">
              <span>🧪</span>
              <p>No lab reports are available yet.</p>
            </div>
          )}

          <div className="record-list">
            {!labReportsLoading && labReports.map((report) => (
              <article className="record-card" key={report.report_id}>
                <div className="record-card-top">
                  <div>
                    <span className="record-label">LAB REPORT #{report.report_id}</span>
                    <h3>{report.test_name}</h3>
                    <p>{report.doctor_name} {report.doctor_specialty ? `· ${report.doctor_specialty}` : ""}</p>
                  </div>
                  <span className="record-date">{formatDate(report.report_date)}</span>
                </div>
                <div className="record-details-grid">
                  <p><strong>Result</strong><span>{report.test_result || "Not provided"}</span></p>
                  <p><strong>Notes</strong><span>{report.notes || "No additional notes"}</span></p>
                  {report.lab_name && (
                    <p>
                      <strong>Laboratory</strong>
                      <span>
                        {report.lab_name}
                        {report.hospital_name ? ` · ${report.hospital_name}` : ""}
                      </span>
                    </p>
                  )}
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="dashboard-section profile-section" id="profile">
          <div className="section-heading">
            <div>
              <span className="eyebrow">ACCOUNT INFORMATION</span>
              <h2>My Profile</h2>
              <p>Your registered MediLink Health account details.</p>
            </div>
          </div>

          <div className="profile-card">
            <div className="profile-avatar">{initial}</div>
            <div className="profile-information">
              <h3>{user.full_name}</h3>
              <p>{user.email}</p>
              <span className="profile-role">
                Patient Account · {user.account_status || "active"}
              </span>
              <small>
                Member since {formatDate(user.created_at)}
              </small>
            </div>
            <div className="profile-security">
              <span>🔒</span>
              <div>
                <strong>Account protected</strong>
                <small>Your account uses secure authentication.</small>
              </div>
            </div>
          </div>
        </section>

        <footer className="dashboard-footer">
          <strong>MediLink Health</strong>
          <span>Excellence in Healthcare Delivery</span>
          <small>© {new Date().getFullYear()} MediLink Health. Patient Portal.</small>
        </footer>
      </main>
    </div>
  );
}

export default PatientDashboard;
