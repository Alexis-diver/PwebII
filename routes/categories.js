const express = require('express');
const router = express.Router();
const { getConnection } = require('../db');

// Middleware simple para admin (opcional: verifica token/rol en auth)
const requireAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];  // Bearer token
  if (!token) return res.status(401).json({ success: false, message: 'No autorizado' });
  // Aquí integra tu verificación de JWT/rol admin si usas
  next();
};

// GET /api/categories - Listar todas (con jerarquía opcional)
router.get('/', async (req, res) => {
  try {
    const conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT * FROM categories ORDER BY created_at DESC'
    );
    conn.release();
    res.json({ success: true, categories: rows });
  } catch (error) {
    console.error('Error listing categories:', error);
    res.status(500).json({ success: false, message: 'Error al obtener categorías' });
  }
});

// POST /api/categories - Agregar nueva (con parent opcional)
router.post('/', requireAdmin, async (req, res) => {  // Protegido
  const { name, description, parent_category_id } = req.body;
  if (!name || name.trim() === '') {
    return res.status(400).json({ success: false, message: 'El nombre de la categoría es obligatorio.' });
  }
  // Validar parent si se envía
  if (parent_category_id && isNaN(parent_category_id)) {
    return res.status(400).json({ success: false, message: 'ID de padre inválido.' });
  }
  try {
    const conn = await getConnection();
    const [result] = await conn.execute(
      'INSERT INTO categories (name, description, parent_category_id) VALUES (?, ?, ?)',
      [name.trim(), description?.trim() || null, parent_category_id ? parseInt(parent_category_id) : null]
    );
    conn.release();
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Categoría añadida exitosamente.' });
    } else {
      res.status(500).json({ success: false, message: 'Error al añadir categoría.' });
    }
  } catch (error) {
    console.error('Error adding category:', error);
    res.status(500).json({ success: false, message: 'Error al añadir categoría.' });
  }
});

// DELETE /api/categories/:id - Eliminar por ID
router.delete('/:id', requireAdmin, async (req, res) => {  // Protegido
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  try {
    const conn = await getConnection();
    // Opcional: Check si tiene hijos antes de delete (para evitar orphans)
    const [children] = await conn.execute('SELECT COUNT(*) as count FROM categories WHERE parent_category_id = ?', [parseInt(id)]);
    if (children[0].count > 0) {
      return res.status(400).json({ success: false, message: 'No se puede eliminar: tiene subcategorías.' });
    }
    const [result] = await conn.execute(
      'DELETE FROM categories WHERE category_id = ?',
      [parseInt(id)]
    );
    conn.release();
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Categoría eliminada exitosamente.' });
    } else {
      res.status(404).json({ success: false, message: 'Categoría no encontrada.' });
    }
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ success: false, message: 'Error al eliminar categoría.' });
  }
});

module.exports = router;