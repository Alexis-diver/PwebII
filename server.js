const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');  // Para chequeo y lectura de carpetas
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');  // Para testDB (ya usado en auth.js)

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sirve archivos estáticos desde public/ (imgs, CSS del backend)
app.use(express.static(path.join(__dirname, 'public')));

// Chequea/crea carpetas de uploads al inicio (evita errores en multer)
const UPLOAD_IMG_DIR = path.join(__dirname, 'uploaded_img');
const UPLOAD_VID_DIR = path.join(__dirname, 'uploaded_videos');
if (!fs.existsSync(UPLOAD_IMG_DIR)) {
  fs.mkdirSync(UPLOAD_IMG_DIR, { recursive: true });
  console.log('Creada carpeta: uploaded_img');
}
if (!fs.existsSync(UPLOAD_VID_DIR)) {
  fs.mkdirSync(UPLOAD_VID_DIR, { recursive: true });
  console.log('Creada carpeta: uploaded_videos');
}

// Sirve archivos subidos desde las carpetas
app.use('/uploaded_img', express.static(UPLOAD_IMG_DIR));
app.use('/uploaded_videos', express.static(UPLOAD_VID_DIR));
console.log('Archivos subidos servidos en /uploaded_img y /uploaded_videos');

// NUEVO: Endpoint debug para listar imágenes en uploaded_img (útil para verificar)
app.get('/debug/images', (req, res) => {
  fs.readdir(UPLOAD_IMG_DIR, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Error leyendo carpeta' });
    }
    const images = files.filter(f => /\.(jpg|jpeg|png|gif)$/i.test(f));
    res.json({ 
      images, 
      count: images.length, 
      dir: UPLOAD_IMG_DIR,
      sampleUrls: images.slice(0, 3).map(img => `http://localhost:${PORT}/uploaded_img/${img}`)
    });
  });
});
console.log('Endpoint debug /debug/images agregado');

// DB_CONFIG para testDB (mismo que en auth.js)
const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'shop_db',
  charset: 'utf8mb4'
};

// Función testDB para startup
async function testDB() {
  try {
    console.log('🔍 Test DB startup...');
    const conn = await mysql.createConnection(DB_CONFIG);
    console.log('✅ ¡Conexión a MySQL exitosa! DB:', DB_CONFIG.database);

    // Test query: COUNT users
    const [countRows] = await conn.execute('SELECT COUNT(*) as count FROM users');
    console.log('📊 Tabla users tiene', countRows[0].count, 'registros al startup');

    // Si 0, avisa
    if (countRows[0].count === 0) {
      console.log('⚠️  AVISO: Tabla users VACÍA — inserta datos en phpMyAdmin o usa /api/auth/admin/test-user');
    }

    await conn.end();
  } catch (error) {
    console.error('💥 ERROR en conexión DB startup:', error.message);
    if (error.code === 'ER_BAD_DB_ERROR') console.log('🔧 FIX: Checa nombre DB en .env o phpMyAdmin (¿"shop_db" exacto?)');
    if (error.code === 'ER_ACCESS_DENIED_ERROR') console.log('🔧 FIX: User/pass malo en .env (root/"" suele jalar)');
  }
}

// Mounting rutas
app.use('/api/auth', require('./routes/auth'));
console.log('Rutas auth montadas en /api/auth — DEBUG: Verifica logs en /admin/users');

app.use('/api/products', require('./routes/products'));
console.log('Rutas products montadas en /api/products');

app.use('/api/header', require('./routes/header'));
console.log('Rutas header montadas en /api/header');

// Ruta de prueba raíz
app.get('/', (req, res) => {
  console.log('Request to / received');
  res.json({ message: '¡API Node.js funcionando en puerto 5000!' });
});

// Middleware global para loggear errores
app.use((err, req, res, next) => {
  console.error('Error global en request:', err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Inicia el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  testDB();  // Llama al test de DB al startup
});