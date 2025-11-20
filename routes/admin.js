const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getConnection } = require('../db'); // Ajusta si tu db.js está en otro lugar
const router = express.Router();

// Ruta POST /api/admin/login
router.post('/login', async (req, res) => {
  let conn;
  try {
    const { name, pass } = req.body;

    // Sanitizar inputs (similar a PHP)
    const sanitizedName = name.replace(/[^a-zA-Z0-9]/g, ''); // Básico, sin espacios ni chars raros
    const sanitizedPass = pass;

    if (!sanitizedName || !sanitizedPass) {
      return res.status(400).json({ message: 'Username y password requeridos' });
    }

    // Obtener conexión
    conn = await getConnection();

    // Buscar admin en BD (usando query con params para seguridad)
    const [rows] = await conn.execute(
      'SELECT * FROM admins WHERE name = ?',
      [sanitizedName]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Usuario o password incorrecto!' });
    }

    const admin = rows[0];

    // Verificar password con bcrypt (¡migra de SHA1 si no lo has hecho!)
    const isMatch = await bcrypt.compare(sanitizedPass, admin.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Usuario o password incorrecto!' });
    }

    // Generar JWT (expira en 7 días)
    const token = jwt.sign(
      { adminId: admin.id, name: admin.name },
      process.env.JWT_SECRET || 'tu_secret_super_secreto_cambia_esto',
      { expiresIn: '7d' }
    );

    // Liberar conexión
    conn.release();

    res.status(200).json({
      message: 'Login exitoso',
      token,
      admin: { id: admin.id, name: admin.name }
    });

  } catch (error) {
    if (conn) conn.release();
    console.error('Error en login admin:', error);
    res.status(500).json({ message: 'Error del servidor' });
  }
});

module.exports = router;