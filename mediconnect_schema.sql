-- MediConnect Database Schema for PostgreSQL

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS appointments CASCADE;
DROP TABLE IF EXISTS medicines CASCADE;
DROP TABLE IF EXISTS doctors CASCADE;
DROP TABLE IF EXISTS pharmacies CASCADE;
DROP TABLE IF EXISTS hospitals CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ============================================
-- 1. USERS TABLE (Patients/General Users)
-- ============================================
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone VARCHAR(15),
    address TEXT,
    city VARCHAR(50),
    state VARCHAR(50),
    pincode VARCHAR(10),
    date_of_birth DATE,
    gender VARCHAR(10) CHECK (gender IN ('Male', 'Female', 'Other')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- ============================================
-- 2. HOSPITALS TABLE
-- ============================================
CREATE TABLE hospitals (
    hospital_id SERIAL PRIMARY KEY,
    hospital_name VARCHAR(150) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    address TEXT NOT NULL,
    city VARCHAR(50) NOT NULL,
    state VARCHAR(50) NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    registration_number VARCHAR(50) UNIQUE,
    hospital_type VARCHAR(50) CHECK (hospital_type IN ('Government', 'Private', 'Multi-specialty', 'Clinic')),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- ============================================
-- 3. PHARMACIES TABLE
-- ============================================
CREATE TABLE pharmacies (
    pharmacy_id SERIAL PRIMARY KEY,
    pharmacy_name VARCHAR(150) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    address TEXT NOT NULL,
    city VARCHAR(50) NOT NULL,
    state VARCHAR(50) NOT NULL,
    pincode VARCHAR(10) NOT NULL,
    license_number VARCHAR(50) UNIQUE,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    operating_hours VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- ============================================
-- 4. DOCTORS TABLE
-- ============================================
CREATE TABLE doctors (
    doctor_id SERIAL PRIMARY KEY,
    hospital_id INTEGER NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    specialization VARCHAR(100) NOT NULL,
    qualification VARCHAR(150),
    experience_years INTEGER,
    phone VARCHAR(15),
    email VARCHAR(100),
    consultation_fee DECIMAL(10, 2),
    available_days VARCHAR(100), -- e.g., "Mon,Tue,Wed,Thu,Fri"
    available_time_from TIME,
    available_time_to TIME,
    room_number VARCHAR(20),
    is_available BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id) ON DELETE CASCADE
);

-- ============================================
-- 5. MEDICINES TABLE
-- ============================================
CREATE TABLE medicines (
    medicine_id SERIAL PRIMARY KEY,
    pharmacy_id INTEGER NOT NULL,
    medicine_name VARCHAR(150) NOT NULL,
    generic_name VARCHAR(150),
    manufacturer VARCHAR(100),
    category VARCHAR(50), -- e.g., "Antibiotics", "Pain Relief", "Vitamins"
    dosage_form VARCHAR(50), -- e.g., "Tablet", "Syrup", "Injection"
    strength VARCHAR(50), -- e.g., "500mg", "10ml"
    price DECIMAL(10, 2) NOT NULL,
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    expiry_date DATE,
    requires_prescription BOOLEAN DEFAULT FALSE,
    description TEXT,
    is_available BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacies(pharmacy_id) ON DELETE CASCADE
);

-- ============================================
-- 6. APPOINTMENTS TABLE (Optional - for future extension)
-- ============================================
CREATE TABLE appointments (
    appointment_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    hospital_id INTEGER NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    status VARCHAR(20) DEFAULT 'Scheduled' CHECK (status IN ('Scheduled', 'Completed', 'Cancelled', 'No-show')),
    symptoms TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id) ON DELETE CASCADE,
    FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id) ON DELETE CASCADE
);

-- ============================================
-- INDEXES FOR BETTER QUERY PERFORMANCE
-- ============================================

-- Users indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_city ON users(city);

-- Hospitals indexes
CREATE INDEX idx_hospitals_city ON hospitals(city);
CREATE INDEX idx_hospitals_pincode ON hospitals(pincode);
CREATE INDEX idx_hospitals_name ON hospitals(hospital_name);

-- Pharmacies indexes
CREATE INDEX idx_pharmacies_city ON pharmacies(city);
CREATE INDEX idx_pharmacies_pincode ON pharmacies(pincode);
CREATE INDEX idx_pharmacies_name ON pharmacies(pharmacy_name);

-- Doctors indexes
CREATE INDEX idx_doctors_hospital ON doctors(hospital_id);
CREATE INDEX idx_doctors_specialization ON doctors(specialization);
CREATE INDEX idx_doctors_available ON doctors(is_available);

-- Medicines indexes
CREATE INDEX idx_medicines_pharmacy ON medicines(pharmacy_id);
CREATE INDEX idx_medicines_name ON medicines(medicine_name);
CREATE INDEX idx_medicines_category ON medicines(category);
CREATE INDEX idx_medicines_available ON medicines(is_available);

-- Appointments indexes
CREATE INDEX idx_appointments_user ON appointments(user_id);
CREATE INDEX idx_appointments_doctor ON appointments(doctor_id);
CREATE INDEX idx_appointments_date ON appointments(appointment_date);

-- ============================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- ============================================

-- Function to update timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to all tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_hospitals_updated_at BEFORE UPDATE ON hospitals
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_pharmacies_updated_at BEFORE UPDATE ON pharmacies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_doctors_updated_at BEFORE UPDATE ON doctors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_medicines_updated_at BEFORE UPDATE ON medicines
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON appointments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- SAMPLE DATA FOR TESTING (Optional)
-- ============================================

-- Insert sample hospital
INSERT INTO hospitals (hospital_name, email, password_hash, phone, address, city, state, pincode, registration_number, hospital_type)
VALUES ('City Care Hospital', 'citycare@hospital.com', '$2b$10$samplehash', '9876543210', '123 Main Street', 'Mumbai', 'Maharashtra', '400001', 'REG123456', 'Multi-specialty');

-- Insert sample pharmacy
INSERT INTO pharmacies (pharmacy_name, email, password_hash, phone, address, city, state, pincode, license_number, operating_hours)
VALUES ('HealthPlus Pharmacy', 'healthplus@pharmacy.com', '$2b$10$samplehash', '9876543211', '456 Market Road', 'Mumbai', 'Maharashtra', '400001', 'LIC789012', '9:00 AM - 9:00 PM');

-- Insert sample user
INSERT INTO users (full_name, email, password_hash, phone, city, state, gender)
VALUES ('John Doe', 'john@example.com', '$2b$10$samplehash', '9876543212', 'Mumbai', 'Maharashtra', 'Male');

-- Insert sample doctor (linked to hospital_id = 1)
INSERT INTO doctors (hospital_id, full_name, specialization, qualification, experience_years, consultation_fee, available_days, available_time_from, available_time_to, is_available)
VALUES (1, 'Dr. Sarah Johnson', 'Cardiologist', 'MD, DM Cardiology', 15, 800.00, 'Mon,Tue,Wed,Thu,Fri', '09:00:00', '17:00:00', TRUE);

-- Insert sample medicine (linked to pharmacy_id = 1)
INSERT INTO medicines (pharmacy_id, medicine_name, generic_name, manufacturer, category, dosage_form, strength, price, stock_quantity, requires_prescription, is_available)
VALUES (1, 'Paracetamol', 'Acetaminophen', 'PharmaCorp', 'Pain Relief', 'Tablet', '500mg', 50.00, 200, FALSE, TRUE);