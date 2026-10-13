import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { INITIAL_DATA } from './data/initial-data.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'db.json');

// Ensure upload directory exists
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Middleware
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Database state management
let db = null;

function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf-8');
      db = JSON.parse(raw);
    } else {
      resetDatabase();
    }
  } catch (err) {
    console.error('Error loading db.json, falling back to initial data:', err);
    resetDatabase();
  }
}

function saveDatabase() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    console.error('Error saving db.json:', err);
  }
}

function resetDatabase() {
  db = JSON.parse(JSON.stringify(INITIAL_DATA));
  saveDatabase();
}

loadDatabase();

// --- KEAMANAN SISTEM INFORMASI (KSI) CONFIGURATION & LAB ENGINE ---
// Dibuat untuk praktikum & evaluasi celah keamanan:
// 1. Stored XSS (Forum Diskusi & Komentar)
// 2. IDOR (Akses Nilai & Transkrip Mahasiswa Lain)
// 3. Arbitrary File Upload (Upload Berkas Tugas Tanpa Filter Ekstensi)
// 4. Privilege Escalation (Manipulasi Role Akun Menjadi Admin)
let securityConfig = {
  vulnerableMode: true, // Default: Mode Rentan untuk Praktikum Penetrasi & Pengujian KSI
  lastToggledAt: new Date().toISOString(),
  vulnerabilities: [
    {
      id: 'stored-xss',
      name: 'Stored Cross-Site Scripting (Stored XSS)',
      category: 'OWASP Top 10 A03:2021 - Injection',
      severity: 'HIGH (CVSS 7.5)',
      location: 'Forum Diskusi Kampus & Balasan Komentar (/api/discussions)',
      description: 'Input formulir disimpan ke basis data tanpa sanitasi/escaping HTML, kemudian dirender langsung di browser pengguna lain menggunakan innerHTML.',
      pocPayload: '<img src=x onerror="alert(\'🚨 [KSI Stored XSS Berhasil!] Sesi pengguna: \' + (document.cookie || \'Aktif\'))">',
      impact: 'Session Hijacking, pencurian token sesi kredensial akun mahasiswa/dosen, defacement konten forum.',
      remediation: 'Gunakan HTML escaping (htmlspecialchars / encodeURI) pada output dan sanitasi input dengan library seperti DOMPurify.'
    },
    {
      id: 'idor',
      name: 'Insecure Direct Object Reference (IDOR)',
      category: 'OWASP Top 10 A01:2021 - Broken Access Control',
      severity: 'HIGH (CVSS 7.1)',
      location: 'Akses Nilai KHS & Transkrip Akademik (/api/transcripts/:studentId & /api/grades)',
      description: 'Pengguna mahasiswa (mhs_1) dapat mengakses seluruh nilai dan transkrip mahasiswa lain (mhs_2) cukup dengan mengganti parameter studentId di URL tanpa verifikasi hak kepemilikan sesi.',
      pocPayload: 'Buka endpoint /api/transcripts/mhs_2 saat login sebagai akun mahasiswa mhs_1 (Ahmad Zulfikar).',
      impact: 'Pelanggaran kerahasiaan data pribadi akademik mahasiswa (Confidentiality Breach) sesuai regulasi UU PDP.',
      remediation: 'Terapkan validasi otorisasi sisi server (Server-Side Authorization Middleware) berbasis session/JWT untuk memastikan requesterId === targetId atau memiliki peran Dosen/Admin.'
    },
    {
      id: 'arbitrary-file-upload',
      name: 'Arbitrary / Unrestricted File Upload',
      category: 'OWASP Top 10 A04:2021 - Insecure Design / RCE',
      severity: 'CRITICAL (CVSS 8.8)',
      location: 'Modul Pengunggahan Berkas Tugas Kuliah LMS (/api/upload & /api/submissions)',
      description: 'Sistem menerima berkas script web berbahaya (.html, .svg, .js, shell) tanpa validasi whitelist ekstensi dan menyimpannya di direktori publik (/uploads/) yang dapat diakses langsung oleh penyerang.',
      pocPayload: 'Unggah file bernama exploit_ksi.html berisi payload JavaScript eksekusi, lalu buka link /uploads/exploit_ksi.html.',
      impact: 'Remote Code Execution (RCE), Stored XSS via File Upload, Hosting Phishing di domain resmi universitas.',
      remediation: 'Terapkan whitelist ekstensi berkas (.pdf, .docx, .zip), validasi MIME type & Magic Bytes, serta ubah nama berkas menjadi hash acak di direktori non-eksekusi.'
    },
    {
      id: 'privilege-escalation',
      name: 'Privilege Escalation (Mass Assignment / Role Tampering)',
      category: 'OWASP Top 10 A01:2021 - Broken Access Control',
      severity: 'HIGH (CVSS 8.5)',
      location: 'Endpoint Pembaruan Data Pengguna (/api/users/:id)',
      description: 'Mahasiswa biasa dapat mengirim body request JSON dengan parameter role: "admin" untuk menaikkan hak akses dirinya sendiri menjadi Administrator sistem.',
      pocPayload: 'Kirim HTTP PUT ke /api/users/mhs_1 dengan JSON body {"role": "admin"}.',
      impact: 'Pengambilalihan penuh sistem (Full System Takeover), modifikasi data akademik dan log audit.',
      remediation: 'Batasi field yang boleh diperbarui (Strict Parameter Whitelisting) dan validasi otorisasi Admin di server sebelum memodifikasi atribut role/status.'
    }
  ]
};

function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Helper to log audit trail
function addAuditLog(userId, userName, userRole, action, details, req) {
  const ip = (req && req.headers && req.headers['x-forwarded-for']) || (req && req.socket && req.socket.remoteAddress) || '127.0.0.1';
  const newLog = {
    id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
    timestamp: new Date().toISOString(),
    userId,
    userName,
    userRole,
    action,
    details,
    ipAddress: ip
  };
  db.auditLogs.unshift(newLog);
  if (db.auditLogs.length > 100) db.auditLogs.pop();
  saveDatabase();
}

// Calculate grade letter and point from numerical score
function computeGradeLetterAndPoint(score) {
  if (score >= 85) return { letter: 'A', point: 4.00 };
  if (score >= 80) return { letter: 'A-', point: 3.75 };
  if (score >= 75) return { letter: 'B+', point: 3.25 };
  if (score >= 70) return { letter: 'B', point: 3.00 };
  if (score >= 65) return { letter: 'B-', point: 2.75 };
  if (score >= 60) return { letter: 'C+', point: 2.25 };
  if (score >= 55) return { letter: 'C', point: 2.00 };
  if (score >= 40) return { letter: 'D', point: 1.00 };
  return { letter: 'E', point: 0.00 };
}

// --- API ROUTES ---

// 1. Initial State / Config / Demo Accounts
app.get('/api/config', (req, res) => {
  res.json({
    university: db.university,
    security: {
      vulnerableMode: securityConfig.vulnerableMode
    },
    demoAccounts: db.users.map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      role: u.role,
      avatar: u.avatar,
      subtext: u.role === 'mahasiswa' ? `NIM ${u.nim} • ${u.prodi}` :
               u.role === 'dosen' ? `${u.jabatan}` : `${u.department}`
    }))
  });
});

// 2. Auth: Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => 
    (u.username.toLowerCase() === username.toLowerCase() || 
     u.email.toLowerCase() === username.toLowerCase() ||
     (u.nim && u.nim === username) ||
     (u.nip && u.nip === username)) &&
    u.password === password
  );

  if (!user) {
    return res.status(401).json({ success: false, message: 'NIM/NIP atau kata sandi tidak valid' });
  }

  if (user.status === 'Nonaktif') {
    return res.status(403).json({ success: false, message: 'Akun Anda sedang dinonaktifkan oleh Administrator.' });
  }

  addAuditLog(user.id, user.name, user.role, 'LOGIN_BERHASIL', `Pengguna ${user.name} (${user.role}) berhasil masuk ke sistem`, req);
  res.json({ success: true, user });
});

// 3. User Management (Admin CRUD & Privilege Escalation Vulnerability Check)
app.get('/api/users', (req, res) => {
  const { role, query } = req.query;
  let list = db.users;

  if (role && role !== 'all') {
    list = list.filter(u => u.role === role);
  }

  if (query) {
    const q = query.toLowerCase();
    list = list.filter(u => 
      u.name.toLowerCase().includes(q) ||
      u.email.toLowerCase().includes(q) ||
      (u.nim && u.nim.includes(q)) ||
      (u.nip && u.nip.includes(q)) ||
      (u.prodi && u.prodi.toLowerCase().includes(q))
    );
  }

  res.json(list);
});

app.post('/api/users', (req, res) => {
  const { role, name, email, prodi, fakultas, angkatan, semester, nip, nidn, jabatan, department } = req.body;
  if (!name || !email || !role) {
    return res.status(400).json({ success: false, message: 'Nama, Email, dan Peran wajib diisi' });
  }

  // Check unique email
  if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ success: false, message: 'Email sudah terdaftar untuk pengguna lain' });
  }

  const newId = `${role === 'mahasiswa' ? 'mhs' : role === 'dosen' ? 'dos' : 'adm'}_${Date.now()}`;
  let newUser = {
    id: newId,
    name,
    email,
    role,
    password: 'password123',
    status: 'Aktif',
    avatar: `https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80`
  };

  if (role === 'mahasiswa') {
    const randomNim = `24040${Math.floor(1000 + Math.random() * 9000)}`;
    newUser = {
      ...newUser,
      username: randomNim,
      nim: randomNim,
      prodi: prodi || 'S1 Teknik Informatika',
      fakultas: fakultas || 'Fakultas Ilmu Komputer & Rekayasa',
      angkatan: angkatan || 2024,
      semester: semester || 1,
      ipk: 0.00,
      totalSks: 0,
      dosenPa: 'Dr. Ir. Hendra Kusuma, M.Kom.',
      enrolledCourses: ['AI402', 'RPL301']
    };
  } else if (role === 'dosen') {
    const randomNip = nip || `19950101${Math.floor(1000000000 + Math.random() * 9000000000)}`;
    newUser = {
      ...newUser,
      username: randomNip,
      nip: randomNip,
      nidn: nidn || `04010195${Math.floor(10 + Math.random() * 89)}`,
      jabatan: jabatan || 'Asisten Ahli',
      fakultas: fakultas || 'Fakultas Ilmu Komputer & Rekayasa',
      prodi: prodi || 'Teknik Informatika',
      courses: ['AI402']
    };
  } else {
    const admId = `ADM-00${Math.floor(50 + Math.random() * 49)}`;
    newUser = {
      ...newUser,
      username: email.split('@')[0],
      nip: admId,
      jabatan: jabatan || 'Staf Administrasi',
      department: department || 'Biro Administrasi Akademik'
    };
  }

  db.users.push(newUser);
  saveDatabase();
  addAuditLog(req.body.adminId || 'adm_1', req.body.adminName || 'Admin', 'admin', 'BUAT_AKUN_BARU', `Membuat akun baru ${newUser.name} (${newUser.role})`, req);

  res.status(201).json({ success: true, user: newUser });
});

// Update Akun (Dengan demonstrasi celah Privilege Escalation)
app.put('/api/users/:id', (req, res) => {
  const index = db.users.findIndex(u => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan' });

  const current = db.users[index];
  const { name, email, status, prodi, jabatan, semester, ipk, role } = req.body;
  const requesterRole = req.headers['x-user-role'] || req.body.requesterRole;

  // PRIVILEGE ESCALATION CHECK
  if (!securityConfig.vulnerableMode && role && role !== current.role) {
    if (requesterRole !== 'admin') {
      return res.status(403).json({
        success: false,
        blockedBySecurity: true,
        message: '⛔ [Akses Ditolak - Mode Aman]: Pengguna non-admin dilarang memanipulasi hak akses peran (Role Tampering Blocked)!'
      });
    }
  }

  db.users[index] = {
    ...current,
    ...(name && { name }),
    ...(email && { email }),
    ...(status && { status }),
    ...(prodi && { prodi }),
    ...(jabatan && { jabatan }),
    ...(semester && { semester: Number(semester) }),
    ...(ipk !== undefined && { ipk: Number(ipk) }),
    // In vulnerable mode, anyone can escalate their role to 'admin'
    ...(role && { role })
  };

  saveDatabase();
  addAuditLog(
    req.body.adminId || current.id,
    req.body.adminName || current.name,
    db.users[index].role,
    'EDIT_AKUN',
    `Memperbarui data akun ${current.name} (Peran sekarang: ${db.users[index].role})`,
    req
  );

  res.json({
    success: true,
    user: db.users[index],
    message: role === 'admin' && securityConfig.vulnerableMode
      ? `🚨 [Privilege Escalation Berhasil]: Akun ${current.name} sekarang berhasil menjadi ADMINISTRATOR!`
      : `Data akun ${current.name} berhasil diperbarui.`
  });
});

app.patch('/api/users/:id/status', (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan' });

  user.status = user.status === 'Aktif' ? 'Nonaktif' : 'Aktif';
  saveDatabase();
  addAuditLog(req.body.adminId || 'adm_1', req.body.adminName || 'Admin', 'admin', 'TOGGLE_STATUS_AKUN', `Mengubah status akun ${user.name} menjadi ${user.status}`, req);
  res.json({ success: true, user });
});

app.post('/api/users/:id/reset-password', (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan' });

  user.password = 'password123';
  saveDatabase();
  addAuditLog(req.body.adminId || 'adm_1', req.body.adminName || 'Admin', 'admin', 'RESET_PASSWORD', `Mereset password akun ${user.name} ke default`, req);
  res.json({ success: true, message: `Password akun ${user.name} berhasil direset ke: password123` });
});

app.delete('/api/users/:id', (req, res) => {
  const index = db.users.findIndex(u => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ success: false, message: 'Pengguna tidak ditemukan' });

  const deleted = db.users.splice(index, 1)[0];
  saveDatabase();
  addAuditLog(req.body.adminId || 'adm_1', req.body.adminName || 'Admin', 'admin', 'HAPUS_AKUN', `Menghapus akun ${deleted.name} (${deleted.role})`, req);
  res.json({ success: true, message: `Pengguna ${deleted.name} berhasil dihapus` });
});

// 4. Courses API
app.get('/api/courses', (req, res) => {
  const { lecturerId } = req.query;
  let list = db.courses;
  if (lecturerId) {
    list = list.filter(c => c.lecturerId === lecturerId);
  }
  res.json(list);
});

// 5. Grades (KHS & Transkrip) API (Dengan demonstrasi celah IDOR)
app.get('/api/grades', (req, res) => {
  const { studentId, courseId } = req.query;
  const requesterId = req.headers['x-user-id'] || req.query.requesterId;
  const requesterRole = req.headers['x-user-role'] || req.query.requesterRole;

  // IDOR PROTECTION CHECK
  if (!securityConfig.vulnerableMode) {
    if (requesterRole === 'mahasiswa' && studentId && requesterId && requesterId !== studentId) {
      return res.status(403).json({
        success: false,
        idorBlocked: true,
        message: `⛔ [Akses Ditolak - IDOR Protection]: Anda tidak diizinkan mengakses daftar nilai mahasiswa lain!`
      });
    }
  }

  let list = db.grades;

  if (studentId) {
    list = list.filter(g => g.studentId === studentId);
  }
  if (courseId) {
    list = list.filter(g => g.courseId === courseId);
  }

  // Enrich with course details & student details
  const enriched = list.map(g => {
    const course = db.courses.find(c => c.id === g.courseId) || {};
    const student = db.users.find(u => u.id === g.studentId) || {};
    return {
      ...g,
      courseCode: course.code,
      courseName: course.name,
      courseSks: course.sks,
      courseLecturer: course.lecturerName,
      studentName: student.name,
      studentNim: student.nim,
      studentProdi: student.prodi,
      studentAvatar: student.avatar
    };
  });

  res.json(enriched);
});

// Dosen update nilai komponen mahasiswa
app.put('/api/grades/:id', (req, res) => {
  const index = db.grades.findIndex(g => g.id === req.params.id);
  if (index === -1) return res.status(404).json({ success: false, message: 'Data nilai tidak ditemukan' });

  const { tugas, kuis, uts, uas, presensi, notes, lecturerId, lecturerName } = req.body;
  const current = db.grades[index];

  const newTugas = tugas !== undefined ? Number(tugas) : current.tugas;
  const newKuis = kuis !== undefined ? Number(kuis) : current.kuis;
  const newUts = uts !== undefined ? Number(uts) : current.uts;
  const newUas = uas !== undefined ? Number(uas) : current.uas;
  const newPresensi = presensi !== undefined ? Number(presensi) : current.presensi;

  // Bobot: Tugas 20%, Kuis 15%, UTS 30%, UAS 35%
  const finalScore = Number(((newTugas * 0.20) + (newKuis * 0.15) + (newUts * 0.30) + (newUas * 0.35)).toFixed(2));
  const { letter, point } = computeGradeLetterAndPoint(finalScore);

  db.grades[index] = {
    ...current,
    tugas: newTugas,
    kuis: newKuis,
    uts: newUts,
    uas: newUas,
    presensi: newPresensi,
    score: finalScore,
    gradeLetter: letter,
    gradePoint: point,
    status: finalScore >= 55 ? 'Lulus' : 'Tidak Lulus',
    notes: notes !== undefined ? notes : current.notes
  };

  saveDatabase();

  const student = db.users.find(u => u.id === current.studentId);
  const course = db.courses.find(c => c.id === current.courseId);
  addAuditLog(
    lecturerId || 'dos_1',
    lecturerName || 'Dosen',
    'dosen',
    'UPDATE_NILAI_KHS',
    `Memperbarui nilai ${course ? course.code : ''} mahasiswa ${student ? student.name : ''} (Nilai Akhir: ${finalScore} / ${letter})`,
    req
  );

  res.json({ success: true, grade: db.grades[index] });
});

// Transkrip riwayat semester (Demonstrasi Kerentanan IDOR)
app.get('/api/transcripts/:studentId', (req, res) => {
  const targetStudentId = req.params.studentId;
  const requesterId = req.headers['x-user-id'] || req.query.requesterId;
  const requesterRole = req.headers['x-user-role'] || req.query.requesterRole;

  // IDOR PROTECTION CHECK
  if (!securityConfig.vulnerableMode) {
    if (requesterRole === 'mahasiswa' && requesterId && requesterId !== targetStudentId) {
      return res.status(403).json({
        success: false,
        idorBlocked: true,
        message: `⛔ [Akses Ditolak - IDOR Protection]: Anda login sebagai ${requesterId}, tidak memiliki hak akses untuk melihat transkrip milik mahasiswa ${targetStudentId}!`
      });
    }
  }

  const student = db.users.find(u => u.id === targetStudentId);
  if (!student) return res.status(404).json({ success: false, message: 'Mahasiswa tidak ditemukan' });

  // Current active semester grades
  const currentGrades = db.grades.filter(g => g.studentId === student.id).map(g => {
    const course = db.courses.find(c => c.id === g.courseId) || {};
    return {
      code: course.code,
      name: course.name,
      sks: course.sks || 3,
      grade: g.gradeLetter,
      point: g.gradePoint,
      score: g.score
    };
  });

  const currentSks = currentGrades.reduce((sum, c) => sum + c.sks, 0);
  const currentTotalPoint = currentGrades.reduce((sum, c) => sum + (c.sks * c.point), 0);
  const currentIps = currentSks > 0 ? Number((currentTotalPoint / currentSks).toFixed(2)) : 0.00;

  res.json({
    student,
    pastSemesters: db.pastSemesters || [],
    currentSemester: {
      semesterNo: student.semester,
      academicYear: `${db.university.academicYear} ${db.university.semester}`,
      ips: currentIps,
      sks: currentSks,
      courses: currentGrades
    },
    idorStatus: securityConfig.vulnerableMode ? '⚠️ VULNERABLE: Data diakses tanpa verifikasi otorisasi IDOR' : '✅ SECURE: Otorisasi diverifikasi'
  });
});

// 6. Assignments API
app.get('/api/assignments', (req, res) => {
  const { courseId, lecturerId } = req.query;
  let list = db.assignments;
  if (courseId) list = list.filter(a => a.courseId === courseId);
  if (lecturerId) list = list.filter(a => a.lecturerId === lecturerId);
  res.json(list);
});

// Dosen membuat tugas baru
app.post('/api/assignments', (req, res) => {
  const { courseId, lecturerId, lecturerName, title, deadline, description, attachmentName, attachmentSize, maxScore } = req.body;
  if (!courseId || !title || !deadline) {
    return res.status(400).json({ success: false, message: 'Mata kuliah, judul tugas, dan deadline wajib diisi' });
  }

  const course = db.courses.find(c => c.id === courseId);
  const newAssignment = {
    id: `tgs_${Date.now()}`,
    courseId,
    courseName: course ? course.name : courseId,
    lecturerId: lecturerId || (course ? course.lecturerId : 'dos_1'),
    lecturerName: lecturerName || (course ? course.lecturerName : 'Dosen'),
    title,
    deadline,
    description: description || 'Kerjakan tugas sesuai instruksi dan kumpulkan sebelum batas waktu yang ditentukan.',
    attachmentName: attachmentName || 'Panduan_Tugas.pdf',
    attachmentSize: attachmentSize || '1.1 MB',
    maxScore: Number(maxScore) || 100,
    createdAt: new Date().toISOString()
  };

  db.assignments.unshift(newAssignment);
  saveDatabase();

  addAuditLog(lecturerId || 'dos_1', lecturerName || 'Dosen', 'dosen', 'BUAT_TUGAS_BARU', `Membuat tugas baru: "${title}" pada mata kuliah ${course ? course.name : courseId}`, req);
  res.status(201).json({ success: true, assignment: newAssignment });
});

// 7. Submissions API & Arbitrary File Upload
app.get('/api/submissions', (req, res) => {
  const { assignmentId, studentId, courseId } = req.query;
  let list = db.submissions;

  if (assignmentId) list = list.filter(s => s.assignmentId === assignmentId);
  if (studentId) list = list.filter(s => s.studentId === studentId);
  if (courseId) list = list.filter(s => s.courseId === courseId);

  res.json(list);
});

// Mahasiswa mengunggah tugas (Terintegrasi dengan File System Upload)
app.post('/api/submissions', (req, res) => {
  const { assignmentId, studentId, fileName, fileSize, fileData, notes } = req.body;
  if (!assignmentId || !studentId || !fileName) {
    return res.status(400).json({ success: false, message: 'Assignment ID, Student ID, dan Nama File wajib diisi' });
  }

  const ext = path.extname(fileName).toLowerCase();
  const allowedExtensions = ['.pdf', '.docx', '.xlsx', '.zip', '.pptx', '.jpg', '.png'];

  // Check file upload security filter
  if (!securityConfig.vulnerableMode) {
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({
        success: false,
        blockedBySecurity: true,
        message: `⛔ [Akses Ditolak - Ekstensi Berbahaya]: Berkas "${ext}" dilarang demi keamanan sistem! Format yang diizinkan: .pdf, .docx, .zip.`
      });
    }
  }

  // Write file to /public/uploads/ directory
  try {
    const targetFile = path.join(UPLOADS_DIR, fileName);
    if (fileData && fileData.startsWith('data:')) {
      const base64Data = fileData.split(',')[1];
      fs.writeFileSync(targetFile, Buffer.from(base64Data, 'base64'));
    } else {
      fs.writeFileSync(targetFile, fileData || '<!-- Berkas Tugas Mahasiswa Portal Kampus -->', 'utf-8');
    }
  } catch (err) {
    console.error('Gagal menulis berkas submission ke disk:', err);
  }

  const student = db.users.find(u => u.id === studentId);
  const assignment = db.assignments.find(a => a.id === assignmentId);

  const existingIdx = db.submissions.findIndex(s => s.assignmentId === assignmentId && s.studentId === studentId);

  const subData = {
    id: existingIdx !== -1 ? db.submissions[existingIdx].id : `sub_${Date.now()}`,
    assignmentId,
    courseId: assignment ? assignment.courseId : 'AI402',
    studentId,
    studentName: student ? student.name : 'Mahasiswa',
    studentNim: student ? student.nim : '220401001',
    studentProdi: student ? student.prodi : 'S1 Teknik Informatika',
    fileName,
    fileSize: fileSize || '2.4 MB',
    fileUrl: `/uploads/${fileName}`,
    fileData: fileData || null,
    submittedAt: new Date().toISOString(),
    notes: notes || '',
    status: 'submitted',
    score: null,
    feedback: null,
    gradedAt: null,
    gradedBy: null
  };

  if (existingIdx !== -1) {
    db.submissions[existingIdx] = subData;
  } else {
    db.submissions.unshift(subData);
  }

  saveDatabase();

  addAuditLog(
    studentId,
    student ? student.name : 'Mahasiswa',
    'mahasiswa',
    'UNGGAH_TUGAS',
    `Mengunggah berkas "${fileName}" untuk tugas "${assignment ? assignment.title : assignmentId}" (${securityConfig.vulnerableMode ? '⚠️ Unrestricted File Upload' : '✅ Verified Upload'})`,
    req
  );

  res.status(201).json({ success: true, submission: subData });
});

// Standalone Direct Upload Endpoint (Untuk PoC Arbitrary File Upload)
app.post('/api/upload', (req, res) => {
  const { fileName, fileContent, base64Data } = req.body;
  if (!fileName) {
    return res.status(400).json({ success: false, message: 'Nama berkas wajib diisi.' });
  }

  const ext = path.extname(fileName).toLowerCase();
  const allowedExtensions = ['.pdf', '.docx', '.xlsx', '.zip', '.pptx', '.jpg', '.png'];

  if (!securityConfig.vulnerableMode) {
    if (!allowedExtensions.includes(ext)) {
      return res.status(400).json({
        success: false,
        blockedBySecurity: true,
        message: `⛔ [Akses Ditolak - Ekstensi Berbahaya]: Berkas "${ext}" dilarang demi keamanan sistem! Format yang diizinkan: ${allowedExtensions.join(', ')}.`
      });
    }
  }

  const safeFileName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const targetPath = path.join(UPLOADS_DIR, safeFileName);

  try {
    if (base64Data && base64Data.startsWith('data:')) {
      const base64 = base64Data.split(',')[1];
      fs.writeFileSync(targetPath, Buffer.from(base64, 'base64'));
    } else {
      fs.writeFileSync(targetPath, fileContent || '<!-- Berkas Praktikum Eksploitasi KSI -->', 'utf-8');
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Gagal menyimpan berkas ke server: ' + err.message });
  }

  const publicUrl = `/uploads/${safeFileName}`;
  addAuditLog(
    req.body.authorId || 'mhs_1',
    req.body.authorName || 'Mahasiswa',
    'mahasiswa',
    'UPLOAD_LANGSUNG',
    `Mengunggah berkas langsung: ${safeFileName} (${securityConfig.vulnerableMode ? '⚠️ Celah Rentan Aktif' : '✅ Aman'})`,
    req
  );

  res.json({
    success: true,
    fileName: safeFileName,
    url: publicUrl,
    isVulnerable: securityConfig.vulnerableMode,
    message: securityConfig.vulnerableMode
      ? `🚨 [Arbitrary File Upload Berhasil!]: Berkas ${safeFileName} tersimpan di direktori publik server dan dapat diakses/dieksekusi langsung!`
      : `✅ Berkas ${safeFileName} berhasil diunggah dengan aman.`
  });
});

// Dosen memberi nilai tugas
app.put('/api/submissions/:id/grade', (req, res) => {
  const sub = db.submissions.find(s => s.id === req.params.id);
  if (!sub) return res.status(404).json({ success: false, message: 'Submission tidak ditemukan' });

  const { score, feedback, lecturerId, lecturerName } = req.body;
  if (score === undefined) return res.status(400).json({ success: false, message: 'Nilai wajib diisi' });

  sub.score = Number(score);
  sub.feedback = feedback || 'Pekerjaan sudah diperiksa.';
  sub.status = 'graded';
  sub.gradedAt = new Date().toISOString();
  sub.gradedBy = lecturerName || 'Dosen Pengampu';

  saveDatabase();

  addAuditLog(lecturerId || 'dos_1', lecturerName || 'Dosen', 'dosen', 'PENILAIAN_TUGAS', `Memberikan nilai ${sub.score} pada tugas mahasiswa ${sub.studentName} (${sub.studentNim})`, req);
  res.json({ success: true, submission: sub });
});

// 8. Discussions (Forum) API (Dengan demonstrasi celah Stored XSS)
app.get('/api/discussions', (req, res) => {
  const { courseId, category, query } = req.query;
  let list = db.discussions;

  if (courseId && courseId !== 'ALL') {
    list = list.filter(d => d.courseId === courseId || d.courseId === 'ALL');
  }

  if (category && category !== 'ALL') {
    list = list.filter(d => d.category.toLowerCase() === category.toLowerCase());
  }

  if (query) {
    const q = query.toLowerCase();
    list = list.filter(d => 
      d.title.toLowerCase().includes(q) ||
      d.content.toLowerCase().includes(q) ||
      d.authorName.toLowerCase().includes(q) ||
      (d.tags && d.tags.some(t => t.toLowerCase().includes(q)))
    );
  }

  res.json(list);
});

// Create new discussion thread (Stored XSS Point)
app.post('/api/discussions', (req, res) => {
  const { title, category, courseId, content, tags, authorId, authorName, authorRole, authorAvatar, authorSubtext } = req.body;
  if (!title || !content || !authorId) {
    return res.status(400).json({ success: false, message: 'Judul, konten, dan data penulis wajib diisi' });
  }

  // Sanitasi jika Mode Aman aktif; Biarkan mentah (Raw) jika Mode Rentan aktif
  const finalTitle = !securityConfig.vulnerableMode ? sanitizeString(title) : title;
  const finalContent = !securityConfig.vulnerableMode ? sanitizeString(content) : content;

  const course = db.courses.find(c => c.id === courseId);
  const newDisc = {
    id: `disc_${Date.now()}`,
    title: finalTitle,
    category: category || 'Akademik',
    courseId: courseId || 'ALL',
    courseName: course ? course.name : (courseId === 'ALL' ? 'Umum' : courseId),
    authorId,
    authorName,
    authorRole: authorRole || 'mahasiswa',
    authorAvatar: authorAvatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    authorSubtext: authorSubtext || '',
    createdAt: new Date().toISOString(),
    content: finalContent,
    upvotes: 1,
    tags: Array.isArray(tags) ? tags : (tags ? tags.split(',').map(t => t.trim()) : ['Akademik']),
    replies: []
  };

  db.discussions.unshift(newDisc);
  saveDatabase();

  addAuditLog(authorId, authorName, authorRole, 'BUAT_DISKUSI_BARU', `Membuat topik diskusi: "${finalTitle}" (${securityConfig.vulnerableMode ? '⚠️ Raw Stored XSS Allowed' : '✅ Sanitized'})`, req);
  res.status(201).json({ success: true, discussion: newDisc });
});

// Add reply to discussion thread (Stored XSS Point)
app.post('/api/discussions/:id/reply', (req, res) => {
  const disc = db.discussions.find(d => d.id === req.params.id);
  if (!disc) return res.status(404).json({ success: false, message: 'Topik diskusi tidak ditemukan' });

  const { content, authorId, authorName, authorRole, authorAvatar, authorSubtext } = req.body;
  if (!content || !authorId) {
    return res.status(400).json({ success: false, message: 'Konten balasan wajib diisi' });
  }

  // Sanitasi jika Mode Aman aktif
  const finalContent = !securityConfig.vulnerableMode ? sanitizeString(content) : content;

  const newReply = {
    id: `rep_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
    authorId,
    authorName,
    authorRole: authorRole || 'mahasiswa',
    authorAvatar: authorAvatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    authorSubtext: authorSubtext || (authorRole === 'dosen' ? 'Dosen' : 'Mahasiswa'),
    createdAt: new Date().toISOString(),
    content: finalContent,
    isVerifiedAnswer: authorRole === 'dosen',
    upvotes: 0
  };

  disc.replies.push(newReply);
  saveDatabase();

  addAuditLog(authorId, authorName, authorRole, 'BALAS_DISKUSI', `Membalas topik diskusi "${disc.title}" (${securityConfig.vulnerableMode ? '⚠️ Stored XSS Point' : '✅ Sanitized'})`, req);
  res.status(201).json({ success: true, reply: newReply });
});

// Upvote discussion thread or reply
app.post('/api/discussions/:id/upvote', (req, res) => {
  const disc = db.discussions.find(d => d.id === req.params.id);
  if (!disc) return res.status(404).json({ success: false, message: 'Topik diskusi tidak ditemukan' });

  const { replyId } = req.body;
  if (replyId) {
    const reply = disc.replies.find(r => r.id === replyId);
    if (reply) {
      reply.upvotes = (reply.upvotes || 0) + 1;
    }
  } else {
    disc.upvotes = (disc.upvotes || 0) + 1;
  }

  saveDatabase();
  res.json({ success: true, upvotes: replyId ? disc.replies.find(r => r.id === replyId)?.upvotes : disc.upvotes });
});

// Dosen verify / unverify reply as instructor solution
app.patch('/api/discussions/:id/replies/:replyId/verify', (req, res) => {
  const disc = db.discussions.find(d => d.id === req.params.id);
  if (!disc) return res.status(404).json({ success: false, message: 'Topik diskusi tidak ditemukan' });

  const reply = disc.replies.find(r => r.id === req.params.replyId);
  if (!reply) return res.status(404).json({ success: false, message: 'Balasan tidak ditemukan' });

  reply.isVerifiedAnswer = !reply.isVerifiedAnswer;
  saveDatabase();

  addAuditLog(
    req.body.lecturerId || 'dos_1',
    req.body.lecturerName || 'Dosen',
    'dosen',
    'VERIFIKASI_JAWABAN',
    `Menandai balasan pada "${disc.title}" sebagai ${reply.isVerifiedAnswer ? 'Solusi Resmi Dosen' : 'Biasa'}`,
    req
  );

  res.json({ success: true, reply });
});

// 9. KSI Security Status & Toggle Controller
app.get('/api/security/status', (req, res) => {
  res.json({
    vulnerableMode: securityConfig.vulnerableMode,
    vulnerabilities: securityConfig.vulnerabilities,
    studentAuthor: {
      name: 'Putri Sari Rizkiyah',
      email: 'saririzkiyahputri@gmail.com',
      subject: 'Keamanan Sistem Informasi (KSI)',
      university: db.university.name
    }
  });
});

app.post('/api/security/toggle', (req, res) => {
  securityConfig.vulnerableMode = !securityConfig.vulnerableMode;
  securityConfig.lastToggledAt = new Date().toISOString();

  addAuditLog(
    'sec_admin',
    'KSI Lab Security Switch',
    'admin',
    'TOGGLE_SECURITY_MODE',
    `Mode keamanan sistem dialihkan ke: ${securityConfig.vulnerableMode ? '🔴 VULNERABLE (Celah Aktif untuk Uji Praktikum)' : '🟢 PATCHED (Celah Terlindungi / Aman)'}`,
    req
  );

  res.json({
    success: true,
    vulnerableMode: securityConfig.vulnerableMode,
    message: securityConfig.vulnerableMode
      ? '🔴 Mode Rentan Aktif! Celah Stored XSS, IDOR, Arbitrary File Upload, dan Privilege Escalation kini dapat dieksploitasi untuk penilaian praktikum.'
      : '🟢 Mode Aman Aktif! Seluruh celah keamanan telah dipatch (Sanitasi HTML aktif, Otorisasi IDOR aktif, Whitelist Ekstensi aktif).'
  });
});

// 10. Audit Logs API
app.get('/api/audit-logs', (req, res) => {
  res.json(db.auditLogs);
});

// 11. Reset Database to initial state
app.post('/api/reset-data', (req, res) => {
  resetDatabase();
  addAuditLog('adm_1', 'Administrator Sistem', 'admin', 'RESET_MASTER_DATA', 'Mereset seluruh data sintetis ke kondisi default pabrik', req);
  res.json({ success: true, message: 'Database sintetis berhasil direset ke kondisi awal!' });
});

// Fallback to index.html for SPA routes (Express 5 compatible)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` TeknoPortal - Portal Kampus Universitas Teknologi Indonesia`);
  console.log(` Praktikum Keamanan Sistem Informasi (KSI)`);
  console.log(` Mahasiswa : Putri Sari Rizkiyah`);
  console.log(` Server aktif pada: http://localhost:${PORT}`);
  console.log(` Mode Celah : ${securityConfig.vulnerableMode ? '🔴 RENTAN (VULNERABLE)' : '🟢 AMAN (SECURED)'}`);
  console.log(` Status     : Siap Digunakan (Mahasiswa, Dosen, Admin)`);
  console.log(`=======================================================`);
});
