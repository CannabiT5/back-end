require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const verifyToken = require('./middleware/auth'); // ตรวจสอบว่าไฟล์นี้มีอยู่จริง


const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'secret_fallback'; // กัน error ถ้าไม่มี .env

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json());
// ========== DB CONNECTION ==========
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'db_68319010039', // ตรวจสอบชื่อ DB ให้ตรง
});

// ========== TEST ROUTE ==========
app.get('/', (req, res) => {
  res.status(200).send('<h1>Server is fully operational!</h1>');
});

// ========== AUTH: REGISTER / CREATE USER ==========
// ใช้ Route นี้สำหรับการสมัครสมาชิก หรือ เพิ่ม User ใหม่
// URL: http://localhost:3000/users
app.post('/users', async (req, res) => {
  try {
    const { firstname, fullname, lastname, username, password, status } = req.body;

    // 1. Validation
    if (!firstname || !username || !password) {
      return res.status(400).json({ error: 'Firstname, username, and password are required.' });
    }

    if (typeof password !== 'string' || password.trim() === '') {
        return res.status(400).json({ error: 'Password must be a non-empty string.' });
    }

    // 2. Check Duplicate Username
    const [existingUsers] = await db.query('SELECT id FROM tbl_users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    // 3. Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Prepare Data
    // ถ้าไม่ส่ง fullname มา ให้เอา firstname + lastname
    const finalFullname = fullname || `${firstname} ${lastname || ''}`.trim();
    const finalStatus = status || 'user';

    // 5. Insert into DB
    const [result] = await db.query(
      `INSERT INTO tbl_users (firstname, fullname, lastname, username, password, status) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [firstname, finalFullname, lastname, username, hashedPassword, finalStatus]
    );

    // 6. Response
    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: result.insertId,
        username: username,
        fullname: finalFullname,
        status: finalStatus
      }
    });

  } catch (err) {
    console.error('Error in POST /users:', err);
    res.status(500).json({ error: 'Create user failed', details: err.message });
  }
});

// ========== AUTH: LOGIN ==========
// URL: http://localhost:3000/login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    // ค้นหา User
    const [rows] = await db.query('SELECT * FROM tbl_users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = rows[0];

    // เปรียบเทียบรหัสผ่าน (bcrypt)
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

    // สร้าง Token
    const token = jwt.sign(
      { id: user.id, username: user.username, fullname: user.fullname },
      SECRET_KEY,
      { expiresIn: '1h' }
    );
    
    res.json({ message: 'Login successful', token, user: { id: user.id, fullname: user.fullname } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

app.post('/logout', (req, res) => {
  res.json({ message: "Logged out" });
});

// ========== USERS CRUD: GET ALL ==========
app.get('/users', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, firstname, fullname, lastname, username, status FROM tbl_users');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Query failed', details: err.message });
  }
});

// ========== USERS CRUD: GET BY ID ==========
app.get('/users/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await db.query('SELECT id, firstname, fullname, lastname, username, status FROM tbl_users WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Query failed', details: err.message });
  }
});

// ========== USERS CRUD: UPDATE (PUT) ==========
app.put('/users/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { firstname, fullname, lastname, username, password, status } = req.body;

    // Check required fields (ปรับตามความเหมาะสม)
    if (!firstname || !username) {
      return res.status(400).json({ error: 'firstname and username are required' });
    }

    // Check duplicate username (except self)
    const [existingUser] = await db.query('SELECT id FROM tbl_users WHERE username = ? AND id != ?', [username, id]);
    if (existingUser.length > 0) {
        return res.status(409).json({ error: 'Username already taken' });
    }

    let query = 'UPDATE tbl_users SET firstname=?, fullname=?, lastname=?, username=?, status=?';
    let params = [firstname, fullname, lastname, username, status || 'user'];

    // ถ้ามีการส่ง password มาใหม่ ให้ hash ก่อนอัปเดต
    if (password && password.trim() !== '') {
        const hashedPassword = await bcrypt.hash(password, 10);
        query += ', password=?';
        params.push(hashedPassword);
    }

    query += ' WHERE id=?';
    params.push(id);

    const [result] = await db.query(query, params);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'User updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

// ========== USERS CRUD: DELETE ==========
app.delete('/users/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await db.query('DELETE FROM tbl_users WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed', details: err.message });
  }
});

// ========== START SERVER ==========
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));