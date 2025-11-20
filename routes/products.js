const express = require('express');
const router = express.Router();
const { getConnection } = require('../db');  // Conexión a tu DB

// GET /api/products (lista productos, con LIMIT opcional como en PHP)
router.get('/', async (req, res) => {
  try {
    const limit = req.query.limit || 6;  // Por defecto 6, como en tu PHP
    const conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT * FROM `products` LIMIT ?', 
      [parseInt(limit)]
    );
    conn.release();
    console.log(`Products sent: ${rows.length}`);  // Debug en terminal backend
    res.json({ success: true, products: rows });
  } catch (error) {
    console.error('Error en products:', error);  // Debug
    res.status(500).json({ success: false, message: 'Error al cargar productos' });
  }
});

// GET /api/products/:id (para quick view o detalle de producto)
router.get('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute('SELECT * FROM `products` WHERE id = ?', [parseInt(id)]);
    conn.release();

    if (rows.length > 0) {
      res.json({ success: true, product: rows[0] });
    } else {
      res.status(404).json({ success: false, message: 'Producto no encontrado' });
    }
  } catch (error) {
    console.error('Error en producto detalle:', error);
    res.status(500).json({ success: false, message: 'Error al cargar producto' });
  }
});

module.exports = router;