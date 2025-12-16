/**
 * Rate Limiter simple en memoria
 * Para producción, considera usar Redis o un servicio externo
 */

const rateLimitStore = new Map();

/**
 * Limpia entradas expiradas del store
 */
function cleanExpiredEntries() {
  const now = Date.now();
  for (const [key, value] of rateLimitStore.entries()) {
    if (value.expiresAt < now) {
      rateLimitStore.delete(key);
    }
  }
}

// Limpiar cada 5 minutos
setInterval(cleanExpiredEntries, 5 * 60 * 1000);

/**
 * Rate limiter middleware
 * @param {Object} options - Opciones de rate limiting
 * @param {number} options.windowMs - Ventana de tiempo en milisegundos
 * @param {number} options.max - Número máximo de requests
 * @param {string} options.message - Mensaje de error personalizado
 */
export function rateLimiter(options = {}) {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutos por defecto
    max = 100, // 100 requests por defecto
    message = 'Demasiadas solicitudes, por favor intenta más tarde',
    keyGenerator = (req) => {
      // Generar clave basada en IP y ruta
      if (!req || !req.headers) {
        return 'unknown:unknown';
      }
      const ip = req.headers['x-forwarded-for'] || 
                 req.headers['x-real-ip'] || 
                 req.connection?.remoteAddress || 
                 req.socket?.remoteAddress ||
                 'unknown';
      const path = req.url || req.path || req.query?.path || '/';
      return `${ip}:${path}`;
    },
  } = options;

  return async (req, res, next) => {
    try {
      // Verificar que req y res existan
      if (!req || !res) {
        if (next) next();
        return;
      }

      const key = keyGenerator(req);
      const now = Date.now();
      
      // Limpiar entradas expiradas
      cleanExpiredEntries();
      
      // Obtener o crear entrada
      let entry = rateLimitStore.get(key);
      
      if (!entry || entry.expiresAt < now) {
        // Crear nueva entrada
        entry = {
          count: 0,
          resetAt: now + windowMs,
          expiresAt: now + windowMs + 60000, // Mantener 1 minuto extra para limpieza
        };
        rateLimitStore.set(key, entry);
      }
      
      // Incrementar contador
      entry.count++;
      
      // Verificar límite
      if (entry.count > max) {
        const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
        
        res.setHeader('Retry-After', retryAfter);
        res.setHeader('X-RateLimit-Limit', max);
        res.setHeader('X-RateLimit-Remaining', 0);
        res.setHeader('X-RateLimit-Reset', new Date(entry.resetAt).toISOString());
        
        // En Next.js, si enviamos respuesta, no llamamos next
        res.status(429).json({
          message,
          retryAfter,
        });
        return;
      }
      
      // Agregar headers de rate limit
      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
      res.setHeader('X-RateLimit-Reset', new Date(entry.resetAt).toISOString());
      
      // En Next.js, si hay next lo llamamos, si no, continuamos
      if (next && typeof next === 'function') {
        next();
      }
    } catch (error) {
      console.error('Error en rate limiter:', error);
      // En caso de error, permitir la request
      if (next && typeof next === 'function') {
        next();
      }
    }
  };
}

/**
 * Rate limiter específico para login
 */
export const loginRateLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 intentos de login
  message: 'Demasiados intentos de inicio de sesión. Por favor intenta en 15 minutos.',
  keyGenerator: (req) => {
    if (!req || !req.headers) {
      return 'login:unknown';
    }
    const ip = req.headers['x-forwarded-for'] || 
               req.headers['x-real-ip'] || 
               req.connection?.remoteAddress || 
               req.socket?.remoteAddress ||
               'unknown';
    return `login:${ip}`;
  },
});

/**
 * Rate limiter específico para registro
 */
export const registerRateLimiter = rateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 3, // 3 registros por hora
  message: 'Demasiados intentos de registro. Por favor intenta en 1 hora.',
  keyGenerator: (req) => {
    if (!req || !req.headers) {
      return 'register:unknown';
    }
    const ip = req.headers['x-forwarded-for'] || 
               req.headers['x-real-ip'] || 
               req.connection?.remoteAddress || 
               req.socket?.remoteAddress ||
               'unknown';
    return `register:${ip}`;
  },
});

/**
 * Rate limiter para APIs generales
 */
export const apiRateLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requests
  message: 'Demasiadas solicitudes. Por favor intenta más tarde.',
});

/**
 * Helper para usar rate limiter en Next.js API routes
 * Retorna true si la request debe continuar, false si fue bloqueada
 */
export async function checkRateLimit(req, res, limiter = apiRateLimiter) {
  // Verificar que req y res existan
  if (!req || !res) {
    console.warn('checkRateLimit: req o res es undefined');
    return true; // Permitir continuar si no podemos verificar
  }

  return new Promise((resolve) => {
    try {
      // limiter ya es una función middleware, no necesita ser llamada
      const handler = typeof limiter === 'function' ? limiter : apiRateLimiter;
      handler(req, res, () => {
        // Si la respuesta ya fue enviada (429), fue bloqueada
        const wasBlocked = res.headersSent && res.statusCode === 429;
        resolve(!wasBlocked);
      });
    } catch (error) {
      console.error('Error en checkRateLimit:', error);
      // En caso de error, permitir continuar
      resolve(true);
    }
  });
}

