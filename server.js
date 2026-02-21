// ============================================
// 1. config/db.js - Database Configuration
// ============================================
const { Pool } = require('pg');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
// const pool = new Pool({
//   user: "postgres",
//   host: "localhost",
//   database: "MediConnect",
//   password: "learning",
//   port: 5432,
// });
pool.connect()
  .then(() => {
    console.log('Connected to PostgreSQL database successfully!');
  })
  .catch((err) => {
    console.error('Failed to connect to PostgreSQL database:', err);
  });

// pool.on('connect', () => {
//   console.log('✅ Database connected successfully');
// });

// pool.on('error', (err) => {
//   console.error('❌ Unexpected database error:', err);
//   process.exit(-1);
// });

module.exports = pool;

// ============================================
// 2. middleware/auth.js - Authentication Middleware
// ============================================

const authMiddleware = (userType) => {
  return async (req, res, next) => {
    try {
      // Get token from header
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({ 
          success: false, 
          message: 'Access denied. No token provided.' 
        });
      }

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check user type if specified
      if (userType && decoded.userType !== userType) {
        return res.status(403).json({ 
          success: false, 
          message: 'Access denied. Insufficient permissions.' 
        });
      }

      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token.' 
      });
    }
  };
};

module.exports = authMiddleware;

// ============================================
// 3. controllers/userController.js - User Controller
// ============================================
// shared requires moved to top; `pool` is defined above

// Generate JWT Token
const generateToken = (id, userType) => {
  return jwt.sign({ id, userType }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// User Registration
const registerUser = async (req, res) => {
    try {
        const { full_name , email, password, phone, address, city, state, pincode, date_of_birth, gender } = req.body;
        
        if (!password || password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password is required and must be at least 6 characters' 
            });
        }
        
        console.log('Received password:', password ? 'OK' : 'MISSING');
        
        // Check if user exists
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }
        
        // bcrypt sequence
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);  // Note: passwordHash (camelCase)
        
        // Insert user - USE passwordHash here
        const result = await pool.query(`
            INSERT INTO users (full_name, email, password_hash, phone, address, city, state, pincode, date_of_birth, gender) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
            RETURNING user_id, full_name, email
        `, [full_name, email, passwordHash, phone, address, city, state, pincode, date_of_birth, gender]);
        
        const user = result.rows[0];
        const token = generateToken(user.user_id, 'user');
        
        res.status(201).json({ 
            success: true, 
            message: 'User registered successfully', 
            data: user, 
            token 
        });
        
    } catch (error) {
        console.error('FULL ERROR:', error.message);
        res.status(500).json({ success: false, message: 'Server error', debug: error.message });
    }
};

// User Login
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user exists
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Check password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(user.user_id, 'user');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          user_id: user.user_id,
          full_name: user.full_name,
          email: user.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Search Doctors
const searchDoctors = async (req, res) => {
  try {
    const { specialization, city, hospital_name } = req.query;
    
    let query = `
      SELECT d.*, h.hospital_name, h.address, h.city, h.phone as hospital_phone
      FROM doctors d
      JOIN hospitals h ON d.hospital_id = h.hospital_id
      WHERE d.is_available = true AND h.is_active = true
    `;
    const params = [];
    let paramCount = 1;

    if (specialization) {
      query += ` AND d.specialization ILIKE $${paramCount}`;
      params.push(`%${specialization}%`);
      paramCount++;
    }

    if (city) {
      query += ` AND h.city ILIKE $${paramCount}`;
      params.push(`%${city}%`);
      paramCount++;
    }

    if (hospital_name) {
      query += ` AND h.hospital_name ILIKE $${paramCount}`;
      params.push(`%${hospital_name}%`);
      paramCount++;
    }

    query += ' ORDER BY d.full_name';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Search Medicines
const searchMedicines = async (req, res) => {
  try {
    const { medicine_name, city, category } = req.query;
    
    let query = `
      SELECT m.*, p.pharmacy_name, p.address, p.city, p.phone as pharmacy_phone
      FROM medicines m
      JOIN pharmacies p ON m.pharmacy_id = p.pharmacy_id
      WHERE m.is_available = true AND m.stock_quantity > 0 AND p.is_active = true
    `;
    const params = [];
    let paramCount = 1;

    if (medicine_name) {
      query += ` AND (m.medicine_name ILIKE $${paramCount} OR m.generic_name ILIKE $${paramCount})`;
      params.push(`%${medicine_name}%`);
      paramCount++;
    }

    if (city) {
      query += ` AND p.city ILIKE $${paramCount}`;
      params.push(`%${city}%`);
      paramCount++;
    }

    if (category) {
      query += ` AND m.category ILIKE $${paramCount}`;
      params.push(`%${category}%`);
      paramCount++;
    }

    query += ' ORDER BY m.medicine_name';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  registerUser,
  loginUser,
  searchDoctors,
  searchMedicines
};

// ============================================
// 4. controllers/hospitalController.js
// ============================================
const hospitalRegister = async (req, res) => {
  try {
    const { hospital_name, email, password, phone, address, city, state, pincode, registration_number, hospital_type } = req.body;

    const hospitalExists = await pool.query('SELECT * FROM hospitals WHERE email = $1', [email]);
    if (hospitalExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Hospital already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const result = await pool.query(
      `INSERT INTO hospitals (hospital_name, email, password_hash, phone, address, city, state, pincode, registration_number, hospital_type) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING hospital_id, hospital_name, email`,
      [hospital_name, email, password_hash, phone, address, city, state, pincode, registration_number, hospital_type]
    );

    const hospital = result.rows[0];
    const token = generateToken(hospital.hospital_id, 'hospital');

    res.status(201).json({
      success: true,
      message: 'Hospital registered successfully',
      data: { hospital, token }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const hospitalLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM hospitals WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const hospital = result.rows[0];
    const isMatch = await bcrypt.compare(password, hospital.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(hospital.hospital_id, 'hospital');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        hospital: {
          hospital_id: hospital.hospital_id,
          hospital_name: hospital.hospital_name,
          email: hospital.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  hospitalRegister,
  hospitalLogin
};

// ============================================
// 5. controllers/pharmacyController.js
// ============================================
const pharmacyRegister = async (req, res) => {
  try {
    const { pharmacy_name, email, password, phone, address, city, state, pincode, license_number, operating_hours } = req.body;

    const pharmacyExists = await pool.query('SELECT * FROM pharmacies WHERE email = $1', [email]);
    if (pharmacyExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Pharmacy already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const result = await pool.query(
      `INSERT INTO pharmacies (pharmacy_name, email, password_hash, phone, address, city, state, pincode, license_number, operating_hours) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING pharmacy_id, pharmacy_name, email`,
      [pharmacy_name, email, password_hash, phone, address, city, state, pincode, license_number, operating_hours]
    );

    const pharmacy = result.rows[0];
    const token = generateToken(pharmacy.pharmacy_id, 'pharmacy');

    res.status(201).json({
      success: true,
      message: 'Pharmacy registered successfully',
      data: { pharmacy, token }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const pharmacyLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM pharmacies WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const pharmacy = result.rows[0];
    const isMatch = await bcrypt.compare(password, pharmacy.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(pharmacy.pharmacy_id, 'pharmacy');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        pharmacy: {
          pharmacy_id: pharmacy.pharmacy_id,
          pharmacy_name: pharmacy.pharmacy_name,
          email: pharmacy.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  pharmacyRegister,
  pharmacyLogin
};

// ============================================
// 6. controllers/doctorController.js
// ============================================
const addDoctor = async (req, res) => {
  try {
    const { full_name, specialization, qualification, experience_years, phone, email, consultation_fee, 
            available_days, available_time_from, available_time_to, room_number } = req.body;
    
    const hospital_id = req.user.id; // From auth middleware

    const result = await pool.query(
      `INSERT INTO doctors (hospital_id, full_name, specialization, qualification, experience_years, phone, email, 
       consultation_fee, available_days, available_time_from, available_time_to, room_number) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [hospital_id, full_name, specialization, qualification, experience_years, phone, email, 
       consultation_fee, available_days, available_time_from, available_time_to, room_number]
    );

    res.status(201).json({
      success: true,
      message: 'Doctor added successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const getDoctorsByHospital = async (req, res) => {
  try {
    const hospital_id = req.user.id;

    const result = await pool.query(
      'SELECT * FROM doctors WHERE hospital_id = $1 ORDER BY full_name',
      [hospital_id]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const updateDoctor = async (req, res) => {
  try {
    const { doctor_id } = req.params;
    const hospital_id = req.user.id;
    const updates = req.body;

    // Check if doctor belongs to this hospital
    const checkDoctor = await pool.query(
      'SELECT * FROM doctors WHERE doctor_id = $1 AND hospital_id = $2',
      [doctor_id, hospital_id]
    );

    if (checkDoctor.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Doctor not found' });
    }

    // Build dynamic update query
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');

    const result = await pool.query(
      `UPDATE doctors SET ${setClause} WHERE doctor_id = $${fields.length + 1} AND hospital_id = $${fields.length + 2} RETURNING *`,
      [...values, doctor_id, hospital_id]
    );

    res.json({
      success: true,
      message: 'Doctor updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const deleteDoctor = async (req, res) => {
  try {
    const { doctor_id } = req.params;
    const hospital_id = req.user.id;

    const result = await pool.query(
      'DELETE FROM doctors WHERE doctor_id = $1 AND hospital_id = $2 RETURNING *',
      [doctor_id, hospital_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Doctor not found' });
    }

    res.json({
      success: true,
      message: 'Doctor deleted successfully'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  addDoctor,
  getDoctorsByHospital,
  updateDoctor,
  deleteDoctor
};

// ============================================
// 7. controllers/medicineController.js
// ============================================
const addMedicine = async (req, res) => {
  try {
    const { medicine_name, generic_name, manufacturer, category, dosage_form, strength, price, 
            stock_quantity, expiry_date, requires_prescription, description } = req.body;
    
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      `INSERT INTO medicines (pharmacy_id, medicine_name, generic_name, manufacturer, category, dosage_form, 
       strength, price, stock_quantity, expiry_date, requires_prescription, description) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [pharmacy_id, medicine_name, generic_name, manufacturer, category, dosage_form, 
       strength, price, stock_quantity, expiry_date, requires_prescription, description]
    );

    res.status(201).json({
      success: true,
      message: 'Medicine added successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const getMedicinesByPharmacy = async (req, res) => {
  try {
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      'SELECT * FROM medicines WHERE pharmacy_id = $1 ORDER BY medicine_name',
      [pharmacy_id]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const updateMedicine = async (req, res) => {
  try {
    const { medicine_id } = req.params;
    const pharmacy_id = req.user.id;
    const updates = req.body;

    const checkMedicine = await pool.query(
      'SELECT * FROM medicines WHERE medicine_id = $1 AND pharmacy_id = $2',
      [medicine_id, pharmacy_id]
    );

    if (checkMedicine.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Medicine not found' });
    }

    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');

    const result = await pool.query(
      `UPDATE medicines SET ${setClause} WHERE medicine_id = $${fields.length + 1} AND pharmacy_id = $${fields.length + 2} RETURNING *`,
      [...values, medicine_id, pharmacy_id]
    );

    res.json({
      success: true,
      message: 'Medicine updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const deleteMedicine = async (req, res) => {
  try {
    const { medicine_id } = req.params;
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      'DELETE FROM medicines WHERE medicine_id = $1 AND pharmacy_id = $2 RETURNING *',
      [medicine_id, pharmacy_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Medicine not found' });
    }

    res.json({
      success: true,
      message: 'Medicine deleted successfully'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  addMedicine,
  getMedicinesByPharmacy,
  updateMedicine,
  deleteMedicine
};

// Helper function to generate time slots
const generateTimeSlots = (startTime, endTime, bookedSlots) => {
  const slots = [];
  const start = new Date(`1970-01-01T${startTime}`);
  const end = new Date(`1970-01-01T${endTime}`);
  const interval = 30; // 30 minutes

  let current = new Date(start);
  
  while (current < end) {
    const timeString = current.toTimeString().slice(0, 5); // HH:MM format
    
    // Check if this slot is not booked
    const isBooked = bookedSlots.some(bookedTime => {
      const bookedTimeStr = bookedTime.slice(0, 5);
      return bookedTimeStr === timeString;
    });

    if (!isBooked) {
      slots.push(timeString);
    }

    current = new Date(current.getTime() + interval * 60000);
  }

  return slots;
};

// Check doctor availability for a specific date
const checkDoctorAvailability = async (req, res) => {
  try {
    const { doctor_id, date } = req.query;

    if (!doctor_id || !date) {
      return res.status(400).json({ 
        success: false, 
        message: 'Doctor ID and date are required' 
      });
    }

    // Get doctor details with availability
    const doctorResult = await pool.query(`
      SELECT d.*, h.hospital_name, h.address, h.city 
      FROM doctors d
      JOIN hospitals h ON d.hospital_id = h.hospital_id
      WHERE d.doctor_id = $1 AND d.is_available = true
    `, [doctor_id]);

    if (doctorResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found or not available' 
      });
    }

    const doctor = doctorResult.rows[0];
    
    // console.log('Doctor data:', {
    //   name: doctor.full_name,
    //   available_days: doctor.available_days,
    //   available_time_from: doctor.available_time_from,
    //   available_time_to: doctor.available_time_to
    // });

    // If no available days are set, assume doctor is available all weekdays
    if (!doctor.available_days || doctor.available_days.trim() === '') {
      console.log('No available_days set for doctor, defaulting to Monday-Friday');
      doctor.available_days = 'Monday,Tuesday,Wednesday,Thursday,Friday';
    }

    // Check if the requested date falls on doctor's available days
    const requestedDate = new Date(date + 'T00:00:00'); // Add time to avoid timezone issues
    const dayOfWeek = requestedDate.toLocaleDateString('en-US', { weekday: 'long' });
    
    // Get available days and normalize them
    let availableDays = doctor.available_days.split(',').map(d => d.trim()).filter(d => d !== '');
    
    // Normalize day names to handle variations (Mon, Monday, monday, etc.)
    const dayMap = {
      'mon': 'Monday', 'monday': 'Monday',
      'tue': 'Tuesday', 'tuesday': 'Tuesday',
      'wed': 'Wednesday', 'wednesday': 'Wednesday',
      'thu': 'Thursday', 'thursday': 'Thursday',
      'fri': 'Friday', 'friday': 'Friday',
      'sat': 'Saturday', 'saturday': 'Saturday',
      'sun': 'Sunday', 'sunday': 'Sunday'
    };
    
    // Normalize available days to full day names
    const normalizedDays = availableDays.map(day => {
      const lowerDay = day.toLowerCase();
      return dayMap[lowerDay] || day;
    });
    
    //console.log('Requested day:', dayOfWeek);
    //console.log('Available days (original):', availableDays);
    //console.log('Available days (normalized):', normalizedDays);
    
    // Check if doctor is available on this day
    const isDayAvailable = normalizedDays.some(day => 
      day.toLowerCase() === dayOfWeek.toLowerCase()
    );
    
    if (!isDayAvailable) {
      return res.json({
        success: true,
        available: false,
        message: `Doctor is not available on ${dayOfWeek}. Available days: ${normalizedDays.join(', ')}`,
        doctor: {
          doctor_id: doctor.doctor_id,
          full_name: doctor.full_name,
          specialization: doctor.specialization,
          qualification: doctor.qualification,
          consultation_fee: doctor.consultation_fee,
          hospital_name: doctor.hospital_name,
          hospital_address: doctor.address,
          city: doctor.city
        },
        availableDays: normalizedDays
      });
    }

    // Check if time slots are set
    if (!doctor.available_time_from || !doctor.available_time_to) {
      return res.json({
        success: true,
        available: false,
        message: 'Doctor availability times are not set. Please contact hospital.',
        doctor: {
          doctor_id: doctor.doctor_id,
          full_name: doctor.full_name,
          specialization: doctor.specialization,
          qualification: doctor.qualification,
          consultation_fee: doctor.consultation_fee,
          hospital_name: doctor.hospital_name,
          hospital_address: doctor.address,
          city: doctor.city
        },
        availableDays: normalizedDays
      });
    }

    // Get existing appointments for this doctor on this date
    const appointmentsResult = await pool.query(`
      SELECT appointment_time 
      FROM appointments 
      WHERE doctor_id = $1 
      AND appointment_date = $2 
      AND status IN ('booked', 'confirmed')
      ORDER BY appointment_time
    `, [doctor_id, date]);

    const bookedSlots = appointmentsResult.rows.map(row => row.appointment_time);

    // Generate available time slots (30-minute intervals)
    const availableSlots = generateTimeSlots(
      doctor.available_time_from, 
      doctor.available_time_to, 
      bookedSlots
    );

    //console.log('Generated slots:', availableSlots.length);

    res.json({
      success: true,
      available: availableSlots.length > 0,
      doctor: {
        doctor_id: doctor.doctor_id,
        full_name: doctor.full_name,
        specialization: doctor.specialization,
        qualification: doctor.qualification,
        consultation_fee: doctor.consultation_fee,
        hospital_name: doctor.hospital_name,
        hospital_address: doctor.address,
        city: doctor.city
      },
      date: date,
      dayOfWeek: dayOfWeek,
      availableSlots: availableSlots,
      bookedSlots: bookedSlots,
      availableDays: normalizedDays
    });

  } catch (error) {
    console.error('Error in checkDoctorAvailability:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: error.message 
    });
  }
};

// Book an appointment
const bookAppointment = async (req, res) => {
  try {
    const userid = req.user.id;
    const { doctorid, appointmentdate, appointmenttime, symptoms, notes } = req.body;

    //console.log('=== BOOKING APPOINTMENT ===');
    //console.log('User ID:', userid);
    //console.log('Request body:', req.body);

    // Validate required fields
    if (!doctorid || !appointmentdate || !appointmenttime) {
      return res.status(400).json({ 
        success: false, 
        message: 'Doctor ID, appointment date, and time are required' 
      });
    }

    // Check if doctor exists and is available
    const doctorResult = await pool.query(
      `SELECT doctor_id, hospital_id, full_name 
       FROM doctors 
       WHERE doctor_id = $1 AND is_available = true`, 
      [doctorid]
    );
    
    if (doctorResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Doctor not found or not available' 
      });
    }
    
    const doctor = doctorResult.rows[0];
    console.log('Doctor found:', doctor.full_name);

    // Check if slot is already booked
    const existingAppointment = await pool.query(
      `SELECT appointment_id FROM appointments 
       WHERE doctor_id = $1 
       AND appointment_date = $2 
       AND appointment_time = $3 
       AND status IN ('booked', 'confirmed')`,
      [doctorid, appointmentdate, appointmenttime]
    );
    
    if (existingAppointment.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'This time slot is already booked. Please choose another time.' 
      });
    }

    // Insert appointment with proper column names
    const result = await pool.query(
      `INSERT INTO appointments 
       (user_id, doctor_id, hospital_id, appointment_date, appointment_time, symptoms, notes, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'booked') 
       RETURNING *`,
      [userid, doctorid, doctor.hospital_id, appointmentdate, appointmenttime, symptoms || '', notes || '']
    );

    const appointment = result.rows[0];
    console.log('Appointment created:', appointment.appointment_id);
    
    // Get complete appointment details
    const appointmentDetails = await pool.query(
      `SELECT 
        a.*,
        u.full_name as user_name, 
        u.phone as user_phone,
        d.full_name as doctor_name, 
        d.specialization, 
        d.consultation_fee,
        h.hospital_name, 
        h.address as hospital_address, 
        h.city, 
        h.phone as hospital_phone
       FROM appointments a 
       JOIN users u ON a.user_id = u.user_id 
       JOIN doctors d ON a.doctor_id = d.doctor_id 
       JOIN hospitals h ON a.hospital_id = h.hospital_id 
       WHERE a.appointment_id = $1`,
      [appointment.appointment_id]
    );

    console.log('Appointment booked successfully!');
    
    res.status(201).json({
      success: true,
      message: 'Appointment booked successfully!',
      data: appointmentDetails.rows[0]
    });

  } catch (error) {
    console.error('=== BOOKING ERROR ===');
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    res.status(500).json({ 
      success: false, 
      message: 'Booking failed: ' + error.message 
    });
  }
};


// Get user's appointments
const getUserAppointments = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { status } = req.query;

    let query = `
      SELECT 
        a.*,
        d.full_name as doctor_name,
        d.specialization,
        d.consultation_fee,
        d.phone as doctor_phone,
        h.hospital_name,
        h.address as hospital_address,
        h.city,
        h.phone as hospital_phone
      FROM appointments a
      JOIN doctors d ON a.doctor_id = d.doctor_id
      JOIN hospitals h ON a.hospital_id = h.hospital_id
      WHERE a.user_id = $1
    `;

    const params = [user_id];

    if (status) {
      query += ` AND a.status = $2`;
      params.push(status);
    }

    query += ` ORDER BY a.appointment_date DESC, a.appointment_time DESC`;

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Cancel appointment (user)
const cancelAppointment = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { appointment_id } = req.params;

    // Check if appointment exists and belongs to user
    const appointmentCheck = await pool.query(
      'SELECT * FROM appointments WHERE appointment_id = $1 AND user_id = $2',
      [appointment_id, user_id]
    );

    if (appointmentCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    const appointment = appointmentCheck.rows[0];

    if (appointment.status === 'cancelled') {
      return res.status(400).json({ 
        success: false, 
        message: 'Appointment is already cancelled' 
      });
    }

    if (appointment.status === 'completed') {
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot cancel a completed appointment' 
      });
    }

    // Update appointment status
    const result = await pool.query(
      'UPDATE appointments SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE appointment_id = $2 RETURNING *',
      ['cancelled', appointment_id]
    );

    res.json({
      success: true,
      message: 'Appointment cancelled successfully',
      data: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get hospital's appointments
const getHospitalAppointments = async (req, res) => {
  try {
    const hospital_id = req.user.id;
    const { status, doctor_id, date } = req.query;

    let query = `
      SELECT 
        a.*,
        u.full_name as user_name,
        u.email as user_email,
        u.phone as user_phone,
        d.full_name as doctor_name,
        d.specialization,
        d.room_number
      FROM appointments a
      JOIN users u ON a.user_id = u.user_id
      JOIN doctors d ON a.doctor_id = d.doctor_id
      WHERE a.hospital_id = $1
    `;

    const params = [hospital_id];
    let paramCount = 2;

    if (status) {
      query += ` AND a.status = $${paramCount}`;
      params.push(status);
      paramCount++;
    }

    if (doctor_id) {
      query += ` AND a.doctor_id = $${paramCount}`;
      params.push(doctor_id);
      paramCount++;
    }

    if (date) {
      query += ` AND a.appointment_date = $${paramCount}`;
      params.push(date);
      paramCount++;
    }

    query += ` ORDER BY a.appointment_date DESC, a.appointment_time DESC`;

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update appointment status (hospital)
const updateAppointmentStatus = async (req, res) => {
  try {
    const hospital_id = req.user.id;
    const { appointment_id } = req.params;
    const { status, notes } = req.body;

    // Validate status
    const validStatuses = ['booked', 'confirmed', 'cancelled', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid status' 
      });
    }

    // Check if appointment belongs to this hospital
    const appointmentCheck = await pool.query(
      'SELECT * FROM appointments WHERE appointment_id = $1 AND hospital_id = $2',
      [appointment_id, hospital_id]
    );

    if (appointmentCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Appointment not found' 
      });
    }

    // Update appointment
    const result = await pool.query(
      'UPDATE appointments SET status = $1, notes = COALESCE($2, notes), updated_at = CURRENT_TIMESTAMP WHERE appointment_id = $3 RETURNING *',
      [status, notes, appointment_id]
    );

    res.json({
      success: true,
      message: 'Appointment status updated successfully',
      data: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ============================================
// MEDICINE ORDER FUNCTIONS
// ============================================

// Order Medicine
const orderMedicine = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { medicine_id, quantity, delivery_address, notes } = req.body;

    if (!medicine_id || !quantity || !delivery_address) {
      return res.status(400).json({ 
        success: false, 
        message: 'Medicine ID, quantity, and delivery address are required' 
      });
    }

    // Get medicine details
    const medicineResult = await pool.query(
      'SELECT * FROM medicines WHERE medicine_id = $1 AND is_available = true',
      [medicine_id]
    );

    if (medicineResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Medicine not found or not available' 
      });
    }

    const medicine = medicineResult.rows[0];

    // Check stock
    if (medicine.stock_quantity < quantity) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient stock. Only ${medicine.stock_quantity} units available` 
      });
    }

    // Calculate total price
    const total_price = parseFloat(medicine.price) * parseInt(quantity);

    // Create order
    const result = await pool.query(`
      INSERT INTO medicine_orders 
      (user_id, pharmacy_id, medicine_id, quantity, total_price, delivery_address, 
       prescription_required, notes, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending') 
      RETURNING *
    `, [user_id, medicine.pharmacy_id, medicine_id, quantity, total_price, 
        delivery_address, medicine.requires_prescription, notes]);

    const order = result.rows[0];

    // Get complete order details
    const orderDetails = await pool.query(`
      SELECT 
        o.*,
        u.full_name as user_name,
        u.email as user_email,
        u.phone as user_phone,
        m.medicine_name,
        m.generic_name,
        m.dosage_form,
        m.strength,
        p.pharmacy_name,
        p.address as pharmacy_address,
        p.city,
        p.phone as pharmacy_phone
      FROM medicine_orders o
      JOIN users u ON o.user_id = u.user_id
      JOIN medicines m ON o.medicine_id = m.medicine_id
      JOIN pharmacies p ON o.pharmacy_id = p.pharmacy_id
      WHERE o.order_id = $1
    `, [order.order_id]);

    res.status(201).json({
      success: true,
      message: medicine.requires_prescription 
        ? 'Order placed successfully. Please upload prescription to proceed.' 
        : 'Order placed successfully!',
      data: orderDetails.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get user's orders
const getUserOrders = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { status } = req.query;

    let query = `
      SELECT 
        o.*,
        m.medicine_name,
        m.generic_name,
        m.dosage_form,
        m.strength,
        p.pharmacy_name,
        p.address as pharmacy_address,
        p.city,
        p.phone as pharmacy_phone
      FROM medicine_orders o
      JOIN medicines m ON o.medicine_id = m.medicine_id
      JOIN pharmacies p ON o.pharmacy_id = p.pharmacy_id
      WHERE o.user_id = $1
    `;

    const params = [user_id];

    if (status) {
      query += ` AND o.status = $2`;
      params.push(status);
    }

    query += ` ORDER BY o.created_at DESC`;

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Cancel order (user)
const cancelOrder = async (req, res) => {
  try {
    const user_id = req.user.id;
    const { order_id } = req.params;

    const orderCheck = await pool.query(
      'SELECT * FROM medicine_orders WHERE order_id = $1 AND user_id = $2',
      [order_id, user_id]
    );

    if (orderCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }

    const order = orderCheck.rows[0];

    if (order.status === 'cancelled') {
      return res.status(400).json({ 
        success: false, 
        message: 'Order is already cancelled' 
      });
    }

    if (order.status === 'delivered') {
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot cancel a delivered order' 
      });
    }

    const result = await pool.query(
      'UPDATE medicine_orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE order_id = $2 RETURNING *',
      ['cancelled', order_id]
    );

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      data: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get pharmacy's orders
const getPharmacyOrders = async (req, res) => {
  try {
    const pharmacy_id = req.user.id;
    const { status } = req.query;

    let query = `
      SELECT 
        o.*,
        u.full_name as user_name,
        u.email as user_email,
        u.phone as user_phone,
        u.address as user_address,
        m.medicine_name,
        m.generic_name,
        m.stock_quantity
      FROM medicine_orders o
      JOIN users u ON o.user_id = u.user_id
      JOIN medicines m ON o.medicine_id = m.medicine_id
      WHERE o.pharmacy_id = $1
    `;

    const params = [pharmacy_id];

    if (status) {
      query += ` AND o.status = $2`;
      params.push(status);
    }

    query += ` ORDER BY o.created_at DESC`;

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update order status (pharmacy)
const updateOrderStatus = async (req, res) => {
  try {
    const pharmacy_id = req.user.id;
    const { order_id } = req.params;
    const { status, notes } = req.body;

    const validStatuses = ['pending', 'confirmed', 'processing', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid status' 
      });
    }

    const orderCheck = await pool.query(
      'SELECT * FROM medicine_orders WHERE order_id = $1 AND pharmacy_id = $2',
      [order_id, pharmacy_id]
    );

    if (orderCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }

    // If order is being confirmed, update medicine stock
    if (status === 'confirmed' && orderCheck.rows[0].status === 'pending') {
      await pool.query(
        'UPDATE medicines SET stock_quantity = stock_quantity - $1 WHERE medicine_id = $2',
        [orderCheck.rows[0].quantity, orderCheck.rows[0].medicine_id]
      );
    }

    const result = await pool.query(
      'UPDATE medicine_orders SET status = $1, notes = COALESCE($2, notes), updated_at = CURRENT_TIMESTAMP WHERE order_id = $3 RETURNING *',
      [status, notes, order_id]
    );

    res.json({
      success: true,
      message: 'Order status updated successfully',
      data: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ============================================
// 8. routes/userRoutes.js
// ============================================
const userRouter = express.Router();
// controllers and middleware are defined earlier in this file; no require to avoid redeclaration

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.get('/search/doctors', authMiddleware('user'), searchDoctors);
userRouter.get('/search/medicines', authMiddleware('user'), searchMedicines);
userRouter.get('/appointments/check-availability', authMiddleware('user'), checkDoctorAvailability);
userRouter.post('/appointments', authMiddleware('user'), bookAppointment);
userRouter.get('/appointments', authMiddleware('user'), getUserAppointments);
userRouter.put('/appointments/:appointment_id/cancel', authMiddleware('user'), cancelAppointment);
userRouter.post('/orders', authMiddleware('user'), orderMedicine);
userRouter.get('/orders', authMiddleware('user'), getUserOrders);
userRouter.put('/orders/:order_id/cancel', authMiddleware('user'), cancelOrder);

module.exports = userRouter;

// ============================================
// 9. routes/hospitalRoutes.js
// ============================================
const hospitalRouter = express.Router();
// controllers and middleware are defined earlier in this file; no require to avoid redeclaration

hospitalRouter.post('/register', hospitalRegister);
hospitalRouter.post('/login', hospitalLogin);
hospitalRouter.post('/doctors', authMiddleware('hospital'), addDoctor);
hospitalRouter.get('/doctors', authMiddleware('hospital'), getDoctorsByHospital);
hospitalRouter.put('/doctors/:doctor_id', authMiddleware('hospital'), updateDoctor);
hospitalRouter.delete('/doctors/:doctor_id', authMiddleware('hospital'), deleteDoctor);
hospitalRouter.get('/appointments', authMiddleware('hospital'), getHospitalAppointments);
hospitalRouter.put('/appointments/:appointment_id/status', authMiddleware('hospital'), updateAppointmentStatus);

module.exports = hospitalRouter;

// ============================================
// 10. routes/pharmacyRoutes.js
// ============================================
const pharmacyRouter = express.Router();
// controllers and middleware are defined earlier in this file; no require to avoid redeclaration

pharmacyRouter.post('/register', pharmacyRegister);
pharmacyRouter.post('/login', pharmacyLogin);
pharmacyRouter.post('/medicines', authMiddleware('pharmacy'), addMedicine);
pharmacyRouter.get('/medicines', authMiddleware('pharmacy'), getMedicinesByPharmacy);
pharmacyRouter.put('/medicines/:medicine_id', authMiddleware('pharmacy'), updateMedicine);
pharmacyRouter.delete('/medicines/:medicine_id', authMiddleware('pharmacy'), deleteMedicine);
pharmacyRouter.get('/orders', authMiddleware('pharmacy'), getPharmacyOrders);
pharmacyRouter.put('/orders/:order_id/status', authMiddleware('pharmacy'), updateOrderStatus);

module.exports = pharmacyRouter;

// ============================================
// 11. server.js - Main Server File
// ============================================

const app = express();
const path = require('path');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/public', express.static(path.join('F:/Engineering/5th sem/Mini Project/MediConnect/public', 'public')));
app.use(express.static(path.join('F:/Engineering/5th sem/Mini Project/MediConnect/public', 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_index_complete.html'));
});

app.get('/user-login', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_user_login.html'));
});

app.get('/user-register', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_user_register.html'));
});

app.get('/user-dashboard', (req,res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect','public','user_dashboard_enhanced.html'));
})

app.get('/hospital-login', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_hospital_login.html'));
});

app.get('/hospital-register', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_hospital_register.html'));
});

app.get('/hospital-dashboard', (req,res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect','public','hospital_dashboard_enhanced.html'));
})

app.get('/pharmacy-login', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_pharmacy_login.html'));
});

app.get('/pharmacy-register', (req, res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect', 'public', 'mediconnect_pharmacy_register.html'));
});

app.get('/pharmacy-dashboard', (req,res) => {
  res.sendFile(path.join('F:/Engineering/5th sem/Mini Project/MediConnect','public','pharmacy_dashboard_enhanced.html'));
})

// Routes (use routers defined earlier in this file)
app.use('/api/users', userRouter);
app.use('/api/hospitals', hospitalRouter);
app.use('/api/pharmacies', pharmacyRouter);


// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'MediConnect API is running',
    timestamp: new Date().toISOString()
  });
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 API available at http://localhost:${PORT}/`);
});