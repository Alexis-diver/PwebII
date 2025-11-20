const express = require('express');
const router = express.Router();
const { getConnection } = require('../db');

// Middleware auth (opcional, úsalo solo en rutas protegidas)
const auth = require('../middleware/auth');  // Si no tienes, crea abajo o comenta

// GET /api/cart - Lista items del user (protegido)
router.get('/', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const conn = await getConnection();
    const [rows] = await conn.execute(`
      SELECT c.*, p.name, p.price 
      FROM cart c 
      JOIN products p ON c.product_id = p.id 
      WHERE c.user_id = ? 
      ORDER BY c.created_at DESC
    `, [userId]);
    conn.release();
    res.json({ success: true, cart: rows });
  } catch (err) {
    console.error('Error GET cart:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/cart/add - Agrega/actualiza item (protegido)
router.post('/add', auth, async (req, res) => {
  const { productId, qty = 1 } = req.body;
  const userId = req.user.id;
  try {
    const conn = await getConnection();

    // Chequea si existe
    const [existing] = await conn.execute(
      'SELECT * FROM cart WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );

    let cartItem;
    if (existing.length > 0) {
      // Suma qty
      const newQty = existing[0].quantity + parseInt(qty);
      await conn.execute(
        'UPDATE cart SET quantity = ? WHERE id = ?',
        [newQty, existing[0].id]
      );
      cartItem = { ...existing[0], quantity: newQty };
    } else {
      // Fetch product y inserta
      const [product] = await conn.execute(
        'SELECT id, name, price, image_01 as image FROM products WHERE id = ?',
        [productId]
      );
      if (product.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, message: 'Producto no encontrado' });
      }

      const [result] = await conn.execute(
        'INSERT INTO cart (user_id, product_id, quantity, price, image, name) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, productId, parseInt(qty), product[0].price, product[0].image, product[0].name]
      );
      cartItem = { id: result.insertId, ...product[0], quantity: parseInt(qty) };
    }

    conn.release();
    res.json({ success: true, cartItem });
  } catch (err) {
    console.error('Error POST add cart:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/cart/update - Actualiza qty (protegido)
router.put('/update', auth, async (req, res) => {
  const { cartId, qty } = req.body;
  const userId = req.user.id;
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute(
      'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
      [parseInt(qty), cartId, userId]
    );
    if (rows.affectedRows === 0) {
      conn.release();
      return res.status(404).json({ success: false, message: 'Item no encontrado' });
    }
    conn.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Error PUT update cart:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/cart/:id - Borra item (protegido)
router.delete('/:id', auth, async (req, res) => {
  const cartId = req.params.id;
  const userId = req.user.id;
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute(
      'DELETE FROM cart WHERE id = ? AND user_id = ?',
      [cartId, userId]
    );
    if (rows.affectedRows === 0) {
      conn.release();
      return res.status(404).json({ success: false, message: 'Item no encontrado' });
    }
    conn.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Error DELETE cart item:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/cart/delete_all - Borra todo (protegido)
router.delete('/delete_all', auth, async (req, res) => {
  const userId = req.user.id;
  try {
    const conn = await getConnection();
    await conn.execute('DELETE FROM cart WHERE user_id = ?', [userId]);
    conn.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Error DELETE all cart:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;