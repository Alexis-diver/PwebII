const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');  // Para conexiones DB inline (npm install mysql2 si no lo tienes)
const crypto = require('crypto');  // Para sha1 hash (como en tu PHP)
const jwt = require('jsonwebtoken');  // Si no lo tienes, npm install jsonwebtoken
const multer = require('multer');  // Para manejo de uploads
const path = require('path');
const fs = require('fs');  // Para unlink y check exists

// Config DB inline (usa .env o hardcodea — AJUSTADO A TU DB: 'shop_db')
const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'shop_db',  // <-- FIX: Tu DB exacta de phpMyAdmin
  charset: 'utf8mb4'  // Para acentos
};

// Función helper para conexión DB (con debug, usada en todas las rutas)
const getConnection = async () => {
  try {
    console.log('🔍 Intentando conectar a DB:', DB_CONFIG.database);  // DEBUG: Confirma DB usada
    const conn = await mysql.createConnection(DB_CONFIG);  // Conexión simple por query (como PHP)
    console.log('✅ Conexión DB OK para', DB_CONFIG.database);  // DEBUG
    return conn;
  } catch (error) {
    console.error('💥 ERROR en conexión DB:', error.message);  // DEBUG
    throw error;
  }
};

// Paths consistentes (asumiendo uploaded_img y uploaded_videos en root del backend: mi-app-backend/)
const BACKEND_IMG_DIR = path.join(process.cwd(), 'uploaded_img');
const BACKEND_VID_DIR = path.join(process.cwd(), 'uploaded_videos');
const FRONTEND_IMG_DIR = path.join(process.cwd(), '../mi-app-frontend/public/uploaded_img');
const FRONTEND_VID_DIR = path.join(process.cwd(), '../mi-app-frontend/public/uploaded_videos');

// Config Multer para uploads (guarda en carpetas como PHP)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname.startsWith('image_')) {
      cb(null, BACKEND_IMG_DIR);
    } else if (file.fieldname === 'video') {
      cb(null, BACKEND_VID_DIR);
    } else {
      cb(new Error('Tipo de archivo no válido'), false);
    }
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '_' + file.originalname);  // Evita overwrites como en PHP
  }
});
const upload = multer({ storage });

// Middleware para verificar token admin (reutilizable)
const verifyAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: ['No autorizado'] });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'tu_secret_key');
    if (!decoded.adminId) return res.status(401).json({ success: false, message: ['Token no válido para admin'] });
    req.adminId = decoded.adminId;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: ['Token inválido'] });
  }
};

// Middleware para verificar token user (para rutas protegidas de users)
const verifyUser = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: ['No autorizado'] });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'tu_secret_key');
    if (!decoded.id) return res.status(401).json({ success: false, message: ['Token no válido para usuario'] });
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: ['Token inválido'] });
  }
};

// GET /auth/categories (lista categorías) - Actualizado: fetch all fields, protegido para admin
router.get('/categories', verifyAdmin, async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT category_id, name, description, parent_category_id, created_at, updated_at FROM categories ORDER BY name ASC'
    );
    await conn.end();  // Cierra conexión simple
    res.json({ success: true, categories: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en categories:', error);
    res.status(500).json({ success: false, message: ['Error al cargar categorías'] });
  }
});

// POST /auth/categories (añadir categoría) - Nuevo: para admin
router.post('/categories', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { name, description, parent_category_id } = req.body;

    // Sanitize
    const sanitizedName = name.replace(/[^a-zA-Z0-9\s]/g, '').trim();
    const sanitizedDescription = description ? description.replace(/[^a-zA-Z0-9\s.,!?-]/g, '').trim() : null;
    const sanitizedParentId = parent_category_id ? parseInt(parent_category_id) : null;

    // Validación básica
    if (!sanitizedName) {
      return res.status(400).json({ success: false, message: ['El nombre de la categoría es obligatorio'] });
    }

    // Verificar si parent existe (opcional, pero evita orphans inválidos)
    if (sanitizedParentId) {
      conn = await getConnection();
      const [parentRows] = await conn.execute('SELECT category_id FROM categories WHERE category_id = ?', [sanitizedParentId]);
      await conn.end();
      if (parentRows.length === 0) {
        return res.status(400).json({ success: false, message: ['Categoría padre no existe'] });
      }
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check duplicado por nombre (case insensitive simple)
    const [existing] = await conn.execute('SELECT category_id FROM categories WHERE LOWER(name) = LOWER(?)', [sanitizedName]);
    if (existing.length > 0) {
      await conn.rollback();
      await conn.end();
      return res.status(400).json({ success: false, message: ['¡El nombre de la categoría ya existe!'] });
    }

    // Insert
    await conn.execute(
      'INSERT INTO categories (name, description, parent_category_id, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())',
      [sanitizedName, sanitizedDescription, sanitizedParentId]
    );

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: '¡Categoría añadida exitosamente!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en add category:', error);
    res.status(500).json({ success: false, message: ['Error al añadir categoría'] });
  }
});

// DELETE /auth/categories/:id (eliminar categoría) - Nuevo: para admin, simple delete (sin cascade por ahora)
router.delete('/categories/:id', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const categoryId = parseInt(id);

    if (isNaN(categoryId)) {
      return res.status(400).json({ success: false, message: ['ID inválido'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check si existe
    const [existingRows] = await conn.execute('SELECT category_id FROM categories WHERE category_id = ?', [categoryId]);
    if (existingRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Categoría no encontrada'] });
    }

    // Opcional: Check si tiene hijos (evitar delete si tiene)
    const [childrenRows] = await conn.execute('SELECT category_id FROM categories WHERE parent_category_id = ?', [categoryId]);
    if (childrenRows.length > 0) {
      await conn.rollback();
      await conn.end();
      return res.status(400).json({ success: false, message: ['No se puede eliminar: tiene subcategorías'] });
    }

    // Delete (y opcional: update products si usan esta category? Por ahora no, asume manual)
    await conn.execute('DELETE FROM categories WHERE category_id = ?', [categoryId]);

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: '¡Categoría eliminada exitosamente!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en delete category:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar categoría'] });
  }
});

// GET /auth/products (lista productos con filtros: search, category, limit)
router.get('/products', async (req, res) => {
  let conn;
  try {
    const { search = '', category = '', limit = 20 } = req.query;  // Params opcionales
    let query = 'SELECT * FROM products WHERE 1=1';  // Base query
    const params = [];

    if (search) {
      query += ' AND (name LIKE ? OR details LIKE ?)';  // Busca en name y details
      params.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
      query += ' AND category_id = ?';
      params.push(category);
    }
    query += ` ORDER BY id DESC LIMIT ${limit}`;  // Orden descendente, límite

    console.log('Query products:', query, params);  // DEBUG: Mira en server console

    conn = await getConnection();
    const [rows] = await conn.execute(query, params);
    await conn.end();
    console.log(`Productos encontrados: ${rows.length}`);  // DEBUG

    res.json({ success: true, products: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en products list:', error);
    res.status(500).json({ success: false, message: ['Error al cargar productos'] });
  }
});

// GET /auth/orders (lista órdenes del usuario por token)
router.get('/orders', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  let conn;
  try {
    if (!token) return res.status(401).json({ success: false, message: ['No autorizado'] });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'tu_secret_key');
    const userId = decoded.id;

    conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT * FROM orders WHERE user_id = ? ORDER BY placed_on DESC',
      [userId]
    );
    await conn.end();

    console.log(`Órdenes cargadas para user ${userId}: ${rows.length}`);  // DEBUG en server console

    res.json({ success: true, orders: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en orders list:', error);
    res.status(500).json({ success: false, message: ['Error al cargar órdenes'] });
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  const { email, pass } = req.body;
  let conn;
  try {
    const sanitizedEmail = email.replace(/[^a-zA-Z0-9@._-]/g, '');
    const hashedPass = crypto.createHash('sha1').update(pass).digest('hex');

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT id, name, email FROM users WHERE email = ? AND password = ?', [sanitizedEmail, hashedPass]);
    await conn.end();

    if (rows.length > 0) {
      const user = rows[0];
      const userId = user.id;
      const token = jwt.sign({ id: userId }, process.env.JWT_SECRET || 'tu_secret_key', { expiresIn: '1h' });
      res.json({ success: true, message: '¡Inicio de sesión exitoso!', user_id: userId, token, user });
    } else {
      res.status(400).json({ success: false, message: ['incorrect username or password!'] });
    }
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en login:', error);
    res.status(500).json({ success: false, message: ['Error en servidor'] });
  }
});

// POST /auth/register
router.post('/register', async (req, res) => {
  const { name, email, pass, cpass } = req.body;
  let conn;
  try {
    // Sanitize
    const sanitizedName = name.replace(/[^a-zA-Z\s]/g, '').trim();
    const sanitizedEmail = email.replace(/[^a-zA-Z0-9@._-]/g, '');

    const message = [];  // Array para mensajes de error

    // Validación nombre
    if (!/^[a-zA-Z\s]+$/.test(sanitizedName)) {
      message.push('¡El nombre de usuario solo puede contener letras y espacios!');
    }

    // Validación email
    if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(sanitizedEmail)) {
      message.push('¡Formato de correo electrónico inválido!');
    } else {
      const allowedDomains = ['hotmail.com', 'gmail.com', 'outlook.com'];
      const emailDomain = sanitizedEmail.split('@')[1];
      if (!allowedDomains.includes(emailDomain)) {
        message.push('¡El correo electrónico debe ser de los dominios hotmail, gmail u outlook!');
      }
    }

    // Validación password
    if (pass.length < 8) {
      message.push('¡La contraseña debe tener al menos 8 caracteres!');
    }
    if (!/[A-Z]/.test(pass)) {
      message.push('¡La contraseña debe tener al menos una mayúscula!');
    }
    if (!/[a-z]/.test(pass)) {
      message.push('¡La contraseña debe tener al menos una minúscula!');
    }
    if (!/[0-9]/.test(pass)) {
      message.push('¡La contraseña debe tener al menos un número!');
    }
    if (!/[!@#$%^&*()_+{}[\]|\\:;"'<>,.?/~`]/.test(pass)) {
      message.push('¡La contraseña debe tener al menos un carácter especial!');
    }

    if (pass !== cpass) {
      message.push('¡Las contraseñas no coinciden!');
    }

    if (message.length > 0) {
      return res.status(400).json({ success: false, message });
    }

    // Hash password
    const hashedPass = crypto.createHash('sha1').update(pass).digest('hex');

    conn = await getConnection();

    // Check if user exists
    const [existing] = await conn.execute('SELECT id FROM users WHERE email = ?', [sanitizedEmail]);
    if (existing.length > 0) {
      await conn.end();
      return res.status(400).json({ success: false, message: ['¡Email ya registrado!'] });
    }

    // Insert new user
    await conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [sanitizedName, sanitizedEmail, hashedPass]);
    await conn.end();

    res.json({ success: true, message: '¡Registro exitoso, por favor inicia sesión ahora!' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en register:', error);
    res.status(500).json({ success: false, message: ['El registro falló. Por favor, inténtalo de nuevo.'] });
  }
});

// GET /auth/profile (fetch current user por token)
router.get('/profile', verifyUser, async (req, res) => {
  let conn;
  try {
    const userId = req.userId;

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT id, name, email FROM users WHERE id = ?', [userId]);
    await conn.end();

    if (rows.length > 0) {
      res.json({ success: true, user: rows[0] });
    } else {
      res.status(404).json({ success: false, message: ['Usuario no encontrado'] });
    }
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en profile:', error);
    res.status(500).json({ success: false, message: ['Error al cargar perfil'] });
  }
});

// NUEVA RUTA: GET /auth/profile/:id (fetch user por ID, solo si es el owner o admin - pero por ahora, usa verifyUser y chequea ID)
router.get('/profile/:id', verifyUser, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const userId = req.userId;
    const targetId = parseInt(id);

    if (isNaN(targetId)) {
      return res.status(400).json({ success: false, message: ['ID inválido'] });
    }

    // Chequea que sea el propio usuario (o admin, pero por ahora solo owner)
    if (targetId !== userId) {
      return res.status(403).json({ success: false, message: ['No autorizado para ver este perfil'] });
    }

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT id, name, email FROM users WHERE id = ?', [targetId]);
    await conn.end();

    if (rows.length > 0) {
      res.json({ success: true, user: rows[0] });
    } else {
      res.status(404).json({ success: false, message: ['Usuario no encontrado'] });
    }
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en profile/:id:', error);
    res.status(500).json({ success: false, message: ['Error al cargar perfil'] });
  }
});

// PUT /auth/update (update name/email por token)
router.put('/update', verifyUser, async (req, res) => {
  let conn;
  try {
    const { name, email } = req.body;
    const userId = req.userId;

    conn = await getConnection();

    // Check email unique (excepto para este user)
    const [existing] = await conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId]);
    if (existing.length > 0) {
      await conn.end();
      return res.status(400).json({ success: false, message: ['¡Email ya en uso!'] });
    }

    // Update
    await conn.execute('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, userId]);
    await conn.end();

    res.json({ success: true, message: '¡Perfil actualizado!' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en update:', error);
    res.status(500).json({ success: false, message: ['Error al actualizar'] });
  }
});

// POST /auth/cart/add (agregar producto al carrito, requiere token para user_id)
router.post('/cart/add', verifyUser, async (req, res) => {
  let conn;
  const { pid, name, price, image, qty } = req.body;  // Frontend envía qty
  try {
    const userId = req.userId;

    conn = await getConnection();

    // Check if already in cart
    const [existing] = await conn.execute('SELECT id FROM cart WHERE user_id = ? AND pid = ?', [userId, pid]);
    if (existing.length > 0) {
      // Update quantity (usa quantity de la tabla)
      await conn.execute('UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND pid = ?', [qty, userId, pid]);
    } else {
      // Insert new (usa quantity)
      await conn.execute('INSERT INTO cart (user_id, pid, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)', [userId, pid, name, price, image, qty]);
    }

    // Get updated cart count (usa quantity)
    const [cartRows] = await conn.execute('SELECT SUM(quantity) as total FROM cart WHERE user_id = ?', [userId]);
    const cartCount = cartRows[0].total || 0;
    await conn.end();

    res.json({ success: true, message: '¡Producto agregado al carrito!', cartCount });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en add to cart:', error);
    res.status(500).json({ success: false, message: ['Error al agregar al carrito'] });
  }
});

// GET /auth/cart (lista carrito para user_id de token)
router.get('/cart', verifyUser, async (req, res) => {
  let conn;
  try {
    const userId = req.userId;

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT * FROM `user_cart_view` WHERE user_id = ?', [userId]);  // Como en PHP
    await conn.end();

    res.json({ success: true, cart: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en cart:', error);
    res.status(500).json({ success: false, message: ['Error al cargar carrito'] });
  }
});

// PUT /auth/cart/update (update quantity)
router.put('/cart/update', verifyUser, async (req, res) => {
  let conn;
  const { cartId, qty } = req.body;  // Frontend envía qty
  try {
    const userId = req.userId;

    conn = await getConnection();
    await conn.execute('UPDATE `cart` SET quantity = ? WHERE id = ? AND user_id = ?', [qty, cartId, userId]);  // Usa quantity
    await conn.end();

    res.json({ success: true, message: 'Cantidad actualizada' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error update qty:', error);
    res.status(500).json({ success: false, message: ['Error al actualizar'] });
  }
});

// DELETE /auth/cart/:id (delete item)
router.delete('/cart/:id', verifyUser, async (req, res) => {
  let conn;
  const { id } = req.params;
  try {
    const userId = req.userId;

    conn = await getConnection();
    await conn.execute('DELETE FROM `cart` WHERE id = ? AND user_id = ?', [id, userId]);
    await conn.end();

    res.json({ success: true, message: 'Item eliminado' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error delete item:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar'] });
  }
});

// DELETE /auth/cart/delete_all (borrar todo)
router.delete('/cart/delete_all', verifyUser, async (req, res) => {
  let conn;
  try {
    const userId = req.userId;

    conn = await getConnection();
    await conn.execute('DELETE FROM `cart` WHERE user_id = ?', [userId]);
    await conn.end();

    res.json({ success: true, message: 'Carrito borrado' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error delete all:', error);
    res.status(500).json({ success: false, message: ['Error al borrar'] });
  }
});

// GET /auth/product/:id (detalles de producto) - Mejorado con JOIN para category_name
router.get('/product/:id', async (req, res) => {
  let conn;
  const pid = req.params.id;
  try {
    console.log('Fetching product ID:', pid);  // Debug

    conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.category_id WHERE p.id = ?',
      [pid]
    );
    await conn.end();

    console.log('Query result rows:', rows.length);  // Debug

    if (rows.length > 0) {
      console.log('Product loaded:', rows[0].name);  // Debug
      res.json({ success: true, product: rows[0] });
    } else {
      console.log('No product found for ID:', pid);
      res.status(404).json({ success: false, message: 'Producto no encontrado' });
    }
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en product detail:', error);  // Log clave: copia esto si falla
    res.status(500).json({ success: false, message: 'Error al cargar producto' });
  }
});

// POST /auth/add_to_list (agregar a lista)
router.post('/add_to_list', verifyUser, async (req, res) => {
  let conn;
  const { list_id, product_id } = req.body;
  try {
    const userId = req.userId;

    conn = await getConnection();

    // Check if already in list
    const [existing] = await conn.execute('SELECT id FROM user_lists WHERE list_id = ? AND user_id = ? AND product_id = ?', [list_id, userId, product_id]);
    if (existing.length > 0) {
      await conn.end();
      return res.json({ success: false, message: 'Producto ya en la lista' });
    }

    await conn.execute('INSERT INTO user_lists (list_id, user_id, product_id) VALUES (?, ?, ?)', [list_id, userId, product_id]);
    await conn.end();

    res.json({ success: true, message: 'Producto agregado a la lista' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en add to list:', error);
    res.status(500).json({ success: false, message: 'Error al agregar a lista' });
  }
});

// POST /auth/quotation_request (solicitud de cotización)
router.post('/quotation_request', verifyUser, async (req, res) => {
  let conn;
  const { product_id, new_price } = req.body;
  try {
    const userId = req.userId;

    conn = await getConnection();

    // Insert quotation (asumiendo tabla quotations con product_id, user_id, proposed_price, status='pending')
    await conn.execute('INSERT INTO quotations (product_id, user_id, proposed_price, status) VALUES (?, ?, ?, "pending")', [product_id, userId, new_price]);
    await conn.end();

    res.json({ success: true, message: 'Cotización solicitada' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en quotation request:', error);
    res.status(500).json({ success: false, message: 'Error al solicitar cotización' });
  }
});

// POST /auth/comment (agregar comentario/rating)
router.post('/comment', verifyUser, async (req, res) => {
  let conn;
  const { product_id, text, rating } = req.body;
  try {
    const userId = req.userId;

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ success: false, message: 'Rating inválido (1-5)' });
    }
    if (!text.trim()) {
      return res.status(400).json({ success: false, message: 'Comentario vacío' });
    }

    conn = await getConnection();
    await conn.execute('INSERT INTO comments (product_id, user_id, text, rating, created_at) VALUES (?, ?, ?, ?, NOW())', [product_id, userId, text, rating]);
    await conn.end();

    res.json({ success: true, message: 'Comentario agregado' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en comment:', error);
    res.status(500).json({ success: false, message: 'Error al agregar comentario' });
  }
});

// GET /auth/comments/:pid (lista de comentarios)
router.get('/comments/:pid', async (req, res) => {
  let conn;
  const pid = req.params.pid;
  try {
    conn = await getConnection();
    const [rows] = await conn.execute(`
      SELECT c.text, c.rating, c.created_at, u.name
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.product_id = ?
      ORDER BY c.created_at DESC
    `, [pid]);
    await conn.end();

    res.json({ success: true, comments: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en comments:', error);
    res.status(500).json({ success: false, message: 'Error al cargar comentarios' });
  }
});

// GET /auth/lists (fetch user lists)
router.get('/lists', verifyUser, async (req, res) => {
  let conn;
  try {
    const userId = req.userId;

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT * FROM user_lists WHERE user_id = ?', [userId]);
    await conn.end();

    res.json({ success: true, lists: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en lists:', error);
    res.status(500).json({ success: false, message: ['Error al cargar listas'] });
  }
});

// POST /auth/orders (nuevo endpoint para checkout - insert en orders, update stock, clear cart)
router.post('/orders', verifyUser, async (req, res) => {
  let conn;
  const { name, number, email, method, address, total_products, total_price, items } = req.body;  // items para stock
  try {
    const userId = req.userId;

    conn = await getConnection();

    // Sanitize
    const sanitizedName = name.replace(/[^a-zA-Z\s]/g, '').trim();
    const sanitizedNumber = number.replace(/[^0-9]/g, '');
    const sanitizedEmail = email.replace(/[^a-zA-Z0-9@._-]/g, '');
    const sanitizedMethod = method.replace(/[^a-zA-Z\s]/g, '');
    const sanitizedAddress = address.replace(/[^a-zA-Z0-9\s,.-]/g, '');
    const sanitizedTotalProducts = total_products.replace(/[^a-zA-Z0-9\s(),]/g, '');

    if (!items || items.length === 0) {  // JS syntax para empty array
      await conn.end();
      return res.status(400).json({ success: false, message: 'Carrito vacío' });
    }

    await conn.beginTransaction();  // MySQL2 transaction

    // Insert en orders
    const [insertResult] = await conn.execute(`
      INSERT INTO orders (user_id, name, number, email, method, address, total_products, total_price, placed_on, payment_status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURDATE(), 'pending')
    `, [userId, sanitizedName, sanitizedNumber, sanitizedEmail, sanitizedMethod, sanitizedAddress, sanitizedTotalProducts, parseInt(total_price)]);

    const orderId = insertResult.insertId;

    // Update stock para cada item (asume items tienen 'pid')
    for (const item of items) {
      const productId = item.pid || item.product_id;
      const qty = item.quantity;
      if (productId) {
        await conn.execute('UPDATE products SET quantity = quantity - ? WHERE id = ? AND quantity >= ?', [qty, productId, qty]);
      }
    }

    // Clear cart
    await conn.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

    await conn.commit();
    await conn.end();

    console.log(`Orden ${orderId} creada para user ${userId}`);  // Debug log
    res.json({ success: true, message: 'Pedido colocado exitosamente', order_id: orderId });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en orders:', error);  // Log para debug
    res.status(500).json({ success: false, message: 'Error al colocar pedido: ' + error.message });
  }
});

// NUEVA RUTA: POST /auth/admin/login (login para admins)
router.post('/admin/login', async (req, res) => {
  const { name, pass } = req.body;
  let conn;
  try {
    // Sanitizar (similar a PHP y tu login de users)
    const sanitizedName = name.replace(/[^a-zA-Z0-9]/g, '').trim();  // Sin espacios ni chars raros
    const hashedPass = crypto.createHash('sha1').update(pass).digest('hex');

    if (!sanitizedName || !pass) {
      return res.status(400).json({ success: false, message: ['Username y password requeridos'] });
    }

    conn = await getConnection();
    const [rows] = await conn.execute('SELECT id, name FROM admins WHERE name = ? AND password = ?', [sanitizedName, hashedPass]);
    await conn.end();

    if (rows.length > 0) {
      const admin = rows[0];
      const adminId = admin.id;
      // Token con adminId para diferenciar de users
      const token = jwt.sign({ adminId: adminId, name: admin.name }, process.env.JWT_SECRET || 'tu_secret_key', { expiresIn: '7d' });
      res.json({ 
        success: true, 
        message: '¡Inicio de sesión admin exitoso!', 
        admin_id: adminId, 
        token, 
        admin 
      });
    } else {
      res.status(400).json({ success: false, message: ['incorrect username or password!'] });
    }
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en admin login:', error);
    res.status(500).json({ success: false, message: ['Error en servidor'] });
  }
});

// NUEVA RUTA: GET /auth/admin/dashboard (stats para dashboard admin)
router.get('/admin/dashboard', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const adminId = req.adminId;
    conn = await getConnection();

    // Fetch admin name
    const [adminRows] = await conn.execute('SELECT name FROM admins WHERE id = ?', [adminId]);
    if (adminRows.length === 0) {
      await conn.end();
      return res.status(404).json({ success: false, message: ['Admin no encontrado'] });
    }
    const adminName = adminRows[0].name;

    // Total pendings (suma total_price donde payment_status = 'pending')
    const [pendingsRows] = await conn.execute(
      'SELECT SUM(total_price) as total FROM orders WHERE payment_status = ?',
      ['pending']
    );
    const totalPendings = pendingsRows[0].total || 0;

    // Total completes (suma donde 'completed')
    const [completesRows] = await conn.execute(
      'SELECT SUM(total_price) as total FROM orders WHERE payment_status = ?',
      ['completed']
    );
    const totalCompletes = completesRows[0].total || 0;

    // Counts
    const [ordersRows] = await conn.execute('SELECT COUNT(*) as count FROM orders');
    const numOrders = ordersRows[0].count;

    const [productsRows] = await conn.execute('SELECT COUNT(*) as count FROM products');
    const numProducts = productsRows[0].count;

    const [usersRows] = await conn.execute('SELECT COUNT(*) as count FROM users');
    const numUsers = usersRows[0].count;

    const [adminsRows] = await conn.execute('SELECT COUNT(*) as count FROM admins');
    const numAdmins = adminsRows[0].count;

    await conn.end();

    res.json({
      success: true,
      adminName,
      totalPendings,
      totalCompletes,
      numOrders,
      numProducts,
      numUsers,
      numAdmins
    });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en admin dashboard:', error);
    res.status(500).json({ success: false, message: ['Error al cargar dashboard'] });
  }
});

// NUEVA RUTA: POST /auth/admin/products (crear producto)
router.post('/admin/products', upload.fields([
  { name: 'image_01', maxCount: 1 },
  { name: 'image_02', maxCount: 1 },
  { name: 'image_03', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { name, details, price, quantity, category } = req.body;
    const image_01 = req.files['image_01'] ? req.files['image_01'][0].filename : '';
    const image_02 = req.files['image_02'] ? req.files['image_02'][0].filename : '';
    const image_03 = req.files['image_03'] ? req.files['image_03'][0].filename : '';
    const video = req.files['video'] ? req.files['video'][0].filename : '';

    // Sanitize como en PHP
    const sanitizedName = name.replace(/[^a-zA-Z0-9\s]/g, '').trim();
    const sanitizedDetails = details.replace(/[^a-zA-Z0-9\s.,!?-]/g, '').trim();
    const sanitizedPrice = price ? parseFloat(price.replace(/[^0-9.]/g, '')) || null : null;  // Optional, null si vacío
    const sanitizedQuantity = parseInt(quantity.replace(/[^0-9]/g, ''));
    const sanitizedCategory = parseInt(category);

    // Validación: solo required para name, details, quantity, category, image_01 (resto optional)
    if (!sanitizedName || !sanitizedDetails || isNaN(sanitizedQuantity) || isNaN(sanitizedCategory) || !image_01) {
      return res.status(400).json({ success: false, message: ['Campos requeridos faltantes: nombre, detalles, cantidad, categoría e imagen 01'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check duplicado
    const [existing] = await conn.execute('SELECT id FROM products WHERE name = ?', [sanitizedName]);
    if (existing.length > 0) {
      await conn.rollback();
      await conn.end();
      return res.status(400).json({ success: false, message: ['¡El nombre del producto ya existe!'] });
    }

    // Insert (price como null si no se envía)
    await conn.execute(
      'INSERT INTO products (name, details, price, image_01, image_02, image_03, video, quantity, category_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [sanitizedName, sanitizedDetails, sanitizedPrice, image_01, image_02, image_03, video, sanitizedQuantity, sanitizedCategory]
    );

    // Crea carpetas si no existen (backend ya por multer, pero para frontend)
    if (!fs.existsSync(FRONTEND_IMG_DIR)) fs.mkdirSync(FRONTEND_IMG_DIR, { recursive: true });
    if (!fs.existsSync(FRONTEND_VID_DIR)) fs.mkdirSync(FRONTEND_VID_DIR, { recursive: true });

    // Copia files a frontend public (solo si éxito en DB)
    try {
      if (image_01) fs.copyFileSync(path.join(BACKEND_IMG_DIR, image_01), path.join(FRONTEND_IMG_DIR, image_01));
      if (image_02) fs.copyFileSync(path.join(BACKEND_IMG_DIR, image_02), path.join(FRONTEND_IMG_DIR, image_02));
      if (image_03) fs.copyFileSync(path.join(BACKEND_IMG_DIR, image_03), path.join(FRONTEND_IMG_DIR, image_03));
      if (video) fs.copyFileSync(path.join(BACKEND_VID_DIR, video), path.join(FRONTEND_VID_DIR, video));
      
      console.log('Files copiados a mi-app-frontend/public/');  // Debug
    } catch (copyError) {
      console.error('Error al copiar a frontend:', copyError);  // No falla el todo, solo log
    }

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: '¡Nuevo producto agregado!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en add product:', error);
    res.status(500).json({ success: false, message: ['Error al agregar producto'] });
  }
});

// NUEVA RUTA: GET /auth/admin/products (listar con join)
router.get('/admin/products', verifyAdmin, async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const [rows] = await conn.execute(
      'SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.category_id ORDER BY p.name ASC'
    );
    await conn.end();

    res.json({ success: true, products: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en list products:', error);
    res.status(500).json({ success: false, message: ['Error al cargar productos'] });
  }
});

// NUEVA RUTA: DELETE /auth/admin/products/:id (eliminar con unlink)
router.delete('/admin/products/:id', verifyAdmin, async (req, res) => {
  let conn;
  const { id } = req.params;
  try {
    conn = await getConnection();
    await conn.beginTransaction();

    // Fetch para unlink files
    const [productRows] = await conn.execute('SELECT * FROM products WHERE id = ?', [id]);
    if (productRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Producto no encontrado'] });
    }
    const product = productRows[0];

    // Unlink files si existen (backend)
    if (product.image_01 && fs.existsSync(path.join(BACKEND_IMG_DIR, product.image_01))) {
      fs.unlinkSync(path.join(BACKEND_IMG_DIR, product.image_01));
    }
    if (product.image_02 && fs.existsSync(path.join(BACKEND_IMG_DIR, product.image_02))) {
      fs.unlinkSync(path.join(BACKEND_IMG_DIR, product.image_02));
    }
    if (product.image_03 && fs.existsSync(path.join(BACKEND_IMG_DIR, product.image_03))) {
      fs.unlinkSync(path.join(BACKEND_IMG_DIR, product.image_03));
    }
    if (product.video && fs.existsSync(path.join(BACKEND_VID_DIR, product.video))) {
      fs.unlinkSync(path.join(BACKEND_VID_DIR, product.video));
    }

    // Borra copias en frontend public
    if (product.image_01 && fs.existsSync(path.join(FRONTEND_IMG_DIR, product.image_01))) {
      fs.unlinkSync(path.join(FRONTEND_IMG_DIR, product.image_01));
    }
    if (product.image_02 && fs.existsSync(path.join(FRONTEND_IMG_DIR, product.image_02))) {
      fs.unlinkSync(path.join(FRONTEND_IMG_DIR, product.image_02));
    }
    if (product.image_03 && fs.existsSync(path.join(FRONTEND_IMG_DIR, product.image_03))) {
      fs.unlinkSync(path.join(FRONTEND_IMG_DIR, product.image_03));
    }
    if (product.video && fs.existsSync(path.join(FRONTEND_VID_DIR, product.video))) {
      fs.unlinkSync(path.join(FRONTEND_VID_DIR, product.video));
    }

    console.log('Files borrados en backend y frontend');  // Debug

    // Delete
    await conn.execute('DELETE FROM products WHERE id = ?', [id]);
    await conn.execute('DELETE FROM cart WHERE pid = ?', [id]);
    // Opcional: DELETE FROM wishlist WHERE pid = ? (comenta si tabla no existe)
    // await conn.execute('DELETE FROM wishlist WHERE pid = ?', [id]);

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: 'Producto eliminado' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en delete product:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar producto'] });
  }
});

// NUEVA RUTA: GET /auth/admin/orders (lista todas las órdenes para admin)
router.get('/admin/orders', verifyAdmin, async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const [rows] = await conn.execute('SELECT * FROM orders ORDER BY placed_on DESC');  // Trae todo, como en PHP
    await conn.end();
    
    console.log(`Órdenes cargadas para admin ${req.adminId}: ${rows.length}`);  // NUEVO: Debug en consola server — compara con phpMyAdmin
    
    res.json({ success: true, orders: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en admin orders list:', error);
    res.status(500).json({ success: false, message: ['Error al cargar órdenes'] });
  }
});

// NUEVA RUTA: PUT /auth/admin/orders/:id (actualizar payment_status)
router.put('/admin/orders/:id', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const { payment_status } = req.body;
    const orderId = parseInt(id);

    if (isNaN(orderId)) {
      return res.status(400).json({ success: false, message: ['ID de orden inválido'] });
    }

    // Sanitize status (solo pending/completed)
    const sanitizedStatus = (payment_status === 'pending' || payment_status === 'completed') ? payment_status : null;
    if (!sanitizedStatus) {
      return res.status(400).json({ success: false, message: ['Estado inválido: debe ser "pending" o "completed"'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check si existe
    const [existingRows] = await conn.execute('SELECT id FROM orders WHERE id = ?', [orderId]);
    if (existingRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Orden no encontrada'] });
    }

    // Update
    await conn.execute('UPDATE orders SET payment_status = ? WHERE id = ?', [sanitizedStatus, orderId]);

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: '¡Estado de pago actualizado!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en update order status:', error);
    res.status(500).json({ success: false, message: ['Error al actualizar orden'] });
  }
});

// NUEVA RUTA: DELETE /auth/admin/orders/:id (eliminar orden)
router.delete('/admin/orders/:id', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const orderId = parseInt(id);

    if (isNaN(orderId)) {
      return res.status(400).json({ success: false, message: ['ID de orden inválido'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check si existe
    const [existingRows] = await conn.execute('SELECT id FROM orders WHERE id = ?', [orderId]);
    if (existingRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Orden no encontrada'] });
    }

    // Delete (no cascade, asume no hay tablas hijas por ahora)
    await conn.execute('DELETE FROM orders WHERE id = ?', [orderId]);

    await conn.commit();
    await conn.end();

    res.json({ success: true, message: '¡Orden eliminada!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en delete order:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar orden'] });
  }
});

// NUEVA RUTA: GET /auth/admin/users (lista usuarios para admin) - CONEXIÓN INLINE Y DEBUG
router.get('/admin/users', verifyAdmin, async (req, res) => {
  let conn;
  try {
    console.log('Ruta /admin/users alcanzada por adminId:', req.adminId);  // DEBUG: Confirma que llega aquí

    conn = await getConnection();
    console.log('Conexión DB OK para users');  // DEBUG

    // Test count primero (como en PHP)
    const [countRows] = await conn.execute('SELECT COUNT(*) as count FROM `users`');
    console.log('Test: Tabla users tiene', countRows[0].count, 'registros');  // DEBUG CLAVE

    // Query como en PHP: SELECT * FROM `users`
    const [rows] = await conn.execute('SELECT * FROM `users` ORDER BY name ASC');
    console.log('Query ejecutado, rows length:', rows.length, 'primer row:', rows[0] ? rows[0].name : 'vacío');  // DEBUG: Muestra ejemplo

    await conn.end();

    console.log(`Usuarios cargados para admin ${req.adminId}: ${rows.length}`);  // Debug en consola server

    res.json({ success: true, users: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en admin users list:', error.message, error.code, error.sqlMessage || '', error.stack);  // DEBUG: Más detalle en error
    res.status(500).json({ success: false, message: [error.message] });
  }
});

// NUEVA RUTA: DELETE /auth/admin/users/:id (eliminar usuario y datos relacionados)
router.delete('/admin/users/:id', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const userId = parseInt(id);

    if (isNaN(userId)) {
      return res.status(400).json({ success: false, message: ['ID de usuario inválido'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check si existe
    const [existingRows] = await conn.execute('SELECT id FROM users WHERE id = ?', [userId]);
    if (existingRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Usuario no encontrado'] });
    }

    // Cascade deletes (como en PHP: orders, messages, cart, wishlist)
    await conn.execute('DELETE FROM orders WHERE user_id = ?', [userId]);
    await conn.execute('DELETE FROM messages WHERE user_id = ?', [userId]);
    await conn.execute('DELETE FROM cart WHERE user_id = ?', [userId]);
    await conn.execute('DELETE FROM wishlist WHERE user_id = ?', [userId]);  // Asume tabla wishlist existe; comenta si no

    // Opcional: Si users tienen uploads (ej. profile pics), unlink aquí como en products
    // Ejemplo: const [userRows] = await conn.execute('SELECT image FROM users WHERE id = ?', [userId]);
    // if (userRows[0].image && fs.existsSync(path.join(BACKEND_IMG_DIR, userRows[0].image))) { fs.unlinkSync(...); }

    // Delete user
    await conn.execute('DELETE FROM users WHERE id = ?', [userId]);

    await conn.commit();
    await conn.end();

    console.log(`Usuario ${userId} y datos relacionados eliminados por admin ${req.adminId}`);  // Debug

    res.json({ success: true, message: '¡Usuario eliminado exitosamente!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en delete user:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar usuario'] });
  }
});

// RUTA TEMPORAL: POST /auth/admin/test-user (inserta un usuario de prueba para testing - protegida por admin)
router.post('/admin/test-user', verifyAdmin, async (req, res) => {
  let conn;
  try {
    conn = await getConnection();

    // Check si ya existe este test user
    const [existing] = await conn.execute('SELECT id FROM users WHERE email = ?', ['test@example.com']);
    if (existing.length > 0) {
      await conn.end();
      return res.status(400).json({ success: false, message: ['Usuario de prueba ya existe!'] });
    }

    // Insert usuario de prueba (password: 'password123' hashed con SHA1)
    const hashedPass = crypto.createHash('sha1').update('password123').digest('hex');
    await conn.execute('INSERT INTO users (name, email, password, post_count) VALUES (?, ?, ?, 0)', ['Test User', 'test@example.com', hashedPass]);
    await conn.end();

    console.log('Usuario de prueba insertado para testing');  // Debug

    res.json({ success: true, message: '¡Usuario de prueba agregado! Ve a /admin/users_accounts para ver.' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en test-user:', error);
    res.status(500).json({ success: false, message: ['Error al agregar usuario de prueba'] });
  }
});

// NUEVA RUTA: GET /auth/admin/admins (lista admins para admin logueado) - CON DEBUG
router.get('/admin/admins', verifyAdmin, async (req, res) => {
  let conn;
  try {
    console.log('Ruta /admin/admins alcanzada por adminId:', req.adminId);  // DEBUG: Confirma llegada

    conn = await getConnection();
    console.log('Conexión DB OK para admins');  // DEBUG

    // Test count primero
    const [countRows] = await conn.execute('SELECT COUNT(*) as count FROM `admins`');
    console.log('Test: Tabla admins tiene', countRows[0].count, 'registros');  // DEBUG CLAVE — compara con phpMyAdmin

    // Query: SELECT id, name (sin password por seguridad; agrega created_at si existe)
    const [rows] = await conn.execute('SELECT id, name FROM `admins` ORDER BY name ASC');
    console.log('Query admins ejecutada, rows length:', rows.length, 'primer admin:', rows[0] ? rows[0].name : 'vacío');  // DEBUG

    await conn.end();

    console.log(`Admins cargados para admin ${req.adminId}: ${rows.length}`);  // Debug final

    res.json({ success: true, admins: rows });
  } catch (error) {
    if (conn) await conn.end();
    console.error('Error en admin admins list:', error.message, error.code, error.sqlMessage || '');  // DEBUG detallado
    res.status(500).json({ success: false, message: [error.message] });
  }
});

// NUEVA RUTA: DELETE /auth/admin/admins/:id (eliminar admin)
router.delete('/admin/admins/:id', verifyAdmin, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    const adminIdToDelete = parseInt(id);

    if (isNaN(adminIdToDelete)) {
      return res.status(400).json({ success: false, message: ['ID de admin inválido'] });
    }

    // Opcional: Chequea que no sea el propio (pero frontend ya lo hace; aquí extra seguridad)
    if (adminIdToDelete === req.adminId) {
      return res.status(403).json({ success: false, message: ['No puedes eliminar tu propia cuenta'] });
    }

    conn = await getConnection();
    await conn.beginTransaction();

    // Check si existe
    const [existingRows] = await conn.execute('SELECT id FROM admins WHERE id = ?', [adminIdToDelete]);
    if (existingRows.length === 0) {
      await conn.rollback();
      await conn.end();
      return res.status(404).json({ success: false, message: ['Admin no encontrado'] });
    }

    // Delete (asumiendo no hay cascade; si admins tienen relaciones, agrega DELETE FROM ... WHERE admin_id=?)
    await conn.execute('DELETE FROM admins WHERE id = ?', [adminIdToDelete]);

    await conn.commit();
    await conn.end();

    console.log(`Admin ${adminIdToDelete} eliminado por admin ${req.adminId}`);  // Debug

    res.json({ success: true, message: '¡Admin eliminado exitosamente!' });
  } catch (error) {
    if (conn) {
      await conn.rollback();
      await conn.end();
    }
    console.error('Error en delete admin:', error);
    res.status(500).json({ success: false, message: ['Error al eliminar admin'] });
  }
});

// NUEVA RUTA: POST /auth/admin/admins (registrar nuevo admin) - Para /admin/register_admin en React
router.post('/admin/admins', verifyAdmin, async (req, res) => {  // Protegido: solo admins existentes pueden crear más
  let conn;
  try {
    const { name, pass, cpass } = req.body;  // Asume form envía name, pass, cpass
    console.log('📥 POST /admin/admins recibido:', { name, passLength: pass?.length || 0, cpassLength: cpass?.length || 0 }); // DEBUG: Checa input

    // Sanitize
    const sanitizedName = name.replace(/[^a-zA-Z0-9]/g, '').trim();  // Sin espacios ni chars raros, como en login
    const message = [];  // Array para errores

    // Validaciones básicas + longitud para name (tu tabla: varchar 20)
    if (!sanitizedName) {
      message.push('¡El nombre de admin es obligatorio!');
    } else if (sanitizedName.length > 20) {
      message.push('¡El nombre no puede exceder 20 caracteres!');
    }
    if (pass.length < 8) {
      message.push('¡La contraseña debe tener al menos 8 caracteres!');
    }
    if (pass !== cpass) {
      message.push('¡Las contraseñas no coinciden!');
    }

    if (message.length > 0) {
      console.log('❌ Validación falló:', message); // DEBUG
      return res.status(400).json({ success: false, message });
    }

    // Hash password (sha1 como en login) — SHA1 es 40 chars, cabe en varchar 50
    const hashedPass = crypto.createHash('sha1').update(pass).digest('hex');
    console.log('🔐 Password hashed (primeros 10 chars):', hashedPass.substring(0, 10) + '...'); // DEBUG parcial

    conn = await getConnection();
    console.log('✅ Conexión DB OK para insert admin'); // DEBUG

    // Check duplicado por name
    const [existing] = await conn.execute('SELECT id FROM admins WHERE name = ?', [sanitizedName]);
    console.log('🔍 Check duplicado: Encontrados', existing.length); // DEBUG
    if (existing.length > 0) {
      await conn.end();
      return res.status(400).json({ success: false, message: ['¡Nombre de admin ya existe!'] });
    }

    // Insert SIN created_at (ajustado a tu tabla: solo name y password)
    const [insertResult] = await conn.execute('INSERT INTO admins (name, password) VALUES (?, ?)', [sanitizedName, hashedPass]);
    console.log('✅ INSERT admin ejecutado para:', sanitizedName, 'ID nuevo:', insertResult.insertId); // DEBUG éxito

    await conn.end();

    console.log(`Nuevo admin "${sanitizedName}" creado por admin ${req.adminId}`);  // Debug final

    res.json({ success: true, message: '¡Nuevo admin registrado exitosamente! Inicia sesión con sus credenciales.' });
  } catch (error) {
    if (conn) await conn.end();
    console.error('💥 Error en register admin:', error.message, error.code, error.sqlMessage || ''); // DEBUG detallado: ¡copia esto si falla!
    res.status(500).json({ success: false, message: ['Error al registrar admin: ' + (error.sqlMessage || error.message)] }); // Más detalle en response
  }
});

module.exports = router;