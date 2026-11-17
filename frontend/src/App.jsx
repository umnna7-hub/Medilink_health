import AdminDashboard from "./pages/AdminDashboard";
import "./App.css";
import logo from "../medilink-health-transparent (1).png";
import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import PatientDashboard from "./pages/PatientDashboard";
import DoctorDashboard from "./pages/DoctorDashboard";
import AcceptInvite from "./pages/AcceptInvite";
import MfaSetup from "./pages/MfaSetup";
import ProtectedRoute from "./components/ProtectedRoute";

const ADMIN_ROLE = ["admin"];
const DOCTOR_ROLE = ["doctor"];
const PATIENT_ROLE = ["patient"];
const services = [
  {
    icon: "📅",
    title: "Appointments",
    description: "Book and manage consultations from your MediLink account.",
  },
  {
    icon: "🧪",
    title: "Lab Reports",
    description: "View your diagnostic results securely in one place.",
  },
  {
    icon: "📱",
    title: "Web & Mobile Access",
    description: "Stay connected to your healthcare from the web or mobile app.",
  },
  {
    icon: "💳",
    title: "Online Payments",
    description: "Pay online through a secure third-party payment gateway.",
  },
];

const doctors = [
  {
    name: "Dr. Sidra Latif",
    specialty: "General Surgeon",
    image: "photo-1559839734-2b71ea197ec2",
  },
  {
    name: "Dr. Sara Ali",
    specialty: "Neurology",
    image: "photo-1594824476967-48c8b964273f",
  },
  {
    name: "Dr. Usman Malik",
    specialty: "Dermatology",
    image: "photo-1612349317150-e413f6a5b16d",
  },
];

function HomePage() {
  return (
    <div className="app">
      <header className="navbar">
        <a href="#home" className="brand">
          <img src={logo} alt="MediLink Health logo" />
        </a>

        <nav className="nav-links">
          <a href="#home">Home</a>
          <a href="#services">Our Services</a>
          <a href="#doctors">Our Doctors</a>
          <a href="#about">About Us</a>
        </nav>

        <div className="nav-actions">
          <Link to="/login" className="login-link">Log In</Link>
          <Link to="/register" className="nav-button">Get Started ↗</Link>
        </div>
      </header>

      <main>
        <section className="hero" id="home">
          <div className="hero-content">
            <span className="eyebrow">
              EXCELLENCE IN HEALTHCARE DELIVERY
            </span>

            <h1>
              Healthcare that
              <br />
              puts <span>you first.</span>
            </h1>

            <p>
              Use the MediLink web portal or mobile app to book appointments,
              access lab reports, and make online payments through a secure
              third-party gateway.
            </p>

            <div className="hero-actions">
              <Link to="/register" className="primary-button">
                Book an Appointment <span>↗</span>
              </Link>
              <a href="#services" className="secondary-button">
                Explore Services →
              </a>
            </div>

            <div className="trust-note">
              <span className="trust-icon">✓</span>
              Simple. Secure. Patient-focused.
            </div>
          </div>

          <div className="hero-visual">
            <div className="hero-image">
              <img
                src="https://images.unsplash.com/photo-1559839734-2b71ea197ec2?auto=format&fit=crop&w=1000&q=85"
                alt="Healthcare professional"
              />
            </div>

            <div className="floating-card care-card">
              <span className="floating-icon">📅</span>
              <div>
                <strong>Appointments made simple</strong>
                <small>Find and schedule a visit</small>
              </div>
            </div>

            <div className="floating-card appointment-card">
              <span className="appointment-icon">💳</span>
              <div>
                <strong>Secure online payments</strong>
                <small>Processed by a payment provider</small>
              </div>
            </div>
          </div>
        </section>

        <section className="services-section" id="services">
          <div className="section-heading">
            <span className="eyebrow">WHAT WE OFFER</span>
            <h2>Healthcare made <span>simpler.</span></h2>
            <p>Everything you need to take care of your health.</p>
          </div>

          <div className="service-grid">
            {services.map((service) => (
              <article className="service-card" key={service.title}>
                <div className="service-icon">{service.icon}</div>
                <h3>{service.title}</h3>
                <p>{service.description}</p>
                <Link to="/register">Explore more →</Link>
              </article>
            ))}
          </div>
        </section>

        <section className="doctors-section" id="doctors">
          <div className="section-heading">
            <span className="eyebrow">MEET OUR SPECIALISTS</span>
            <h2>Care from people <span>who care.</span></h2>
            <p>Meet our healthcare professionals.</p>
          </div>

          <div className="doctor-grid">
            {doctors.map((doctor) => (
              <article className="doctor-card" key={doctor.name}>
                <img
                  src={`https://images.unsplash.com/${doctor.image}?auto=format&fit=crop&w=600&q=80`}
                  alt={doctor.name}
                />
                <div className="doctor-info">
                  <h3>{doctor.name}</h3>
                  <p>{doctor.specialty}</p>
                  <Link to="/login">Book a visit →</Link>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="about-section" id="about">
          <div>
            <span className="eyebrow">ABOUT MEDILINK</span>
            <h2>Better connections. <span>Better care.</span></h2>
            <p>
              MediLink Health brings essential healthcare services closer
              to patients through a simple, connected and secure digital
              experience.
            </p>
          </div>
          <Link to="/register" className="primary-button">
            Start Your Health Journey ↗
          </Link>
        </section>
      </main>

      <footer className="footer">
        <div className="footer-brand">
          <img src={logo} alt="MediLink Health" />
          <p>Connecting people with better healthcare.</p>
        </div>
        <p>© 2026 MediLink Health. All rights reserved.</p>
      </footer>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
       <Route path="/invite/:token" element={<AcceptInvite />} />
       <Route path="/mfa-setup" element={<MfaSetup />} />
       <Route
         path="/admin-dashboard"
         element={
           <ProtectedRoute allowedRoles={ADMIN_ROLE}>
             <AdminDashboard />
           </ProtectedRoute>
         }
       />
       <Route
         path="/doctor-dashboard"
         element={
           <ProtectedRoute allowedRoles={DOCTOR_ROLE}>
             <DoctorDashboard />
           </ProtectedRoute>
         }
       />
       <Route
         path="/patient-dashboard"
         element={
           <ProtectedRoute allowedRoles={PATIENT_ROLE}>
             <PatientDashboard />
           </ProtectedRoute>
         }
       />
       <Route path="*" element={<main className="not-found-page">
         <h1>Page not found</h1>
         <p>The page you requested does not exist.</p>
         <Link to="/">Return home</Link>
       </main>} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
