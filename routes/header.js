const express = require('express');
const router = express.Router();
const { getConnection } = require('../db');
const jwt = require('jsonwebtoken');  // Para verificar token (instala si no: npm install jsonwebtoken)

// Middleware para auth (para obtener user_id de token)
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ success: false, error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'tu_secret_key');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: 'Token inválido' });
  }
};

// GET /api/header/cart-count (cuenta items en cart)
router.get('/cart-count', authMiddleware, async (req, res) => {
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute('SELECT COUNT(*) as count FROM cart WHERE user_id = ?', [req.user.id]);
    conn.release();
    res.json({ success: true, count: rows[0].count });
  } catch (error) {
    console.error('Error cart:', error);
    res.status(500).json({ success: false, error: 'Error en cart' });
  }
});

// GET /api/header/wishlist-count (cuenta items en wishlist)
router.get('/wishlist-count', authMiddleware, async (req, res) => {
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute('SELECT COUNT(*) as count FROM user_lists WHERE user_id = ?', [req.user.id]);
    conn.release();
    res.json({ success: true, count: rows[0].count });
  } catch (error) {
    console.error('Error wishlist:', error);
    res.status(500).json({ success: false, error: 'Error en wishlist' });
  }
});

// GET /api/header/profile (para $fetch_profile)
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute('SELECT * FROM users WHERE id = ?', [req.user.id]);
    conn.release();
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, user: rows[0] });
  } catch (error) {
    console.error('Error profile:', error);
    res.status(500).json({ success: false, error: 'Error en profile' });
  }
});

module.exports = router;