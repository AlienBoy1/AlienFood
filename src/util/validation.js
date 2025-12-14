/**
 * Utilidades de validación y sanitización para seguridad
 */

// Patrones de validación
const PATTERNS = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  username: /^[a-zA-Z0-9_]{3,20}$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/,
  name: /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,50}$/,
  phone: /^[0-9]{10,15}$/,
  url: /^https?:\/\/.+/,
  objectId: /^[0-9a-fA-F]{24}$/,
};

/**
 * Sanitiza un string eliminando caracteres peligrosos
 */
export function sanitizeString(str, maxLength = 1000) {
  if (typeof str !== 'string') return '';
  
  return str
    .trim()
    .slice(0, maxLength)
    .replace(/[<>]/g, '') // Eliminar < y >
    .replace(/javascript:/gi, '') // Eliminar javascript:
    .replace(/on\w+=/gi, '') // Eliminar event handlers
    .replace(/&lt;/g, '')
    .replace(/&gt;/g, '');
}

/**
 * Sanitiza un objeto completo
 */
export function sanitizeObject(obj, maxDepth = 5) {
  if (maxDepth <= 0) return {};
  
  if (obj === null || obj === undefined) return null;
  
  if (typeof obj !== 'object') {
    return typeof obj === 'string' ? sanitizeString(obj) : obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, maxDepth - 1));
  }
  
  const sanitized = {};
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const sanitizedKey = sanitizeString(key, 100);
      sanitized[sanitizedKey] = sanitizeObject(obj[key], maxDepth - 1);
    }
  }
  
  return sanitized;
}

/**
 * Valida formato de email
 */
export function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const sanitized = sanitizeString(email, 254);
  return PATTERNS.email.test(sanitized);
}

/**
 * Valida formato de username
 */
export function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  return PATTERNS.username.test(username);
}

/**
 * Valida fortaleza de contraseña
 */
export function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  
  // Mínimo 8 caracteres, al menos una mayúscula, una minúscula y un número
  if (password.length < 8) return false;
  if (password.length > 128) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/\d/.test(password)) return false;
  
  return true;
}

/**
 * Valida nombre completo
 */
export function validateName(name) {
  if (!name || typeof name !== 'string') return false;
  const sanitized = sanitizeString(name, 50);
  return PATTERNS.name.test(sanitized) && sanitized.length >= 2;
}

/**
 * Valida ObjectId de MongoDB
 */
export function validateObjectId(id) {
  if (!id || typeof id !== 'string') return false;
  return PATTERNS.objectId.test(id);
}

/**
 * Valida número positivo
 */
export function validatePositiveNumber(num) {
  const number = typeof num === 'string' ? parseFloat(num) : num;
  return !isNaN(number) && number > 0 && isFinite(number);
}

/**
 * Valida número entero positivo
 */
export function validatePositiveInteger(num) {
  const number = typeof num === 'string' ? parseInt(num, 10) : num;
  return !isNaN(number) && number > 0 && Number.isInteger(number);
}

/**
 * Valida que un string no esté vacío
 */
export function validateNotEmpty(str) {
  return typeof str === 'string' && str.trim().length > 0;
}

/**
 * Valida longitud de string
 */
export function validateLength(str, min, max) {
  if (typeof str !== 'string') return false;
  const length = str.trim().length;
  return length >= min && length <= max;
}

/**
 * Valida que un valor esté en un array de valores permitidos
 */
export function validateEnum(value, allowedValues) {
  return allowedValues.includes(value);
}

/**
 * Valida datos de registro
 */
export function validateRegisterData(data) {
  const errors = [];
  
  if (!validateName(data.name)) {
    errors.push('El nombre debe tener entre 2 y 50 caracteres y solo letras');
  }
  
  if (!validateUsername(data.username)) {
    errors.push('El nombre de usuario debe tener entre 3 y 20 caracteres alfanuméricos o guiones bajos');
  }
  
  if (!validateEmail(data.email)) {
    errors.push('El correo electrónico no es válido');
  }
  
  if (!validatePassword(data.password)) {
    errors.push('La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas y números');
  }
  
  if (data.password !== data.confirmPassword) {
    errors.push('Las contraseñas no coinciden');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Valida datos de login
 */
export function validateLoginData(data) {
  const errors = [];
  
  if (!validateNotEmpty(data.username)) {
    errors.push('El nombre de usuario es requerido');
  }
  
  if (!validateNotEmpty(data.password)) {
    errors.push('La contraseña es requerida');
  }
  
  if (data.username && !validateLength(data.username, 3, 20)) {
    errors.push('El nombre de usuario debe tener entre 3 y 20 caracteres');
  }
  
  if (data.password && !validateLength(data.password, 6, 128)) {
    errors.push('La contraseña debe tener entre 6 y 128 caracteres');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Valida datos de actualización de perfil
 */
export function validateProfileUpdateData(data) {
  const errors = [];
  
  if (data.name !== undefined && !validateName(data.name)) {
    errors.push('El nombre debe tener entre 2 y 50 caracteres y solo letras');
  }
  
  if (data.username !== undefined && !validateUsername(data.username)) {
    errors.push('El nombre de usuario debe tener entre 3 y 20 caracteres alfanuméricos o guiones bajos');
  }
  
  if (data.email !== undefined && !validateEmail(data.email)) {
    errors.push('El correo electrónico no es válido');
  }
  
  if (data.password !== undefined && !validatePassword(data.password)) {
    errors.push('La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas y números');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Protege contra inyección NoSQL
 */
export function sanitizeMongoQuery(query) {
  if (typeof query !== 'object' || query === null) return {};
  
  const sanitized = {};
  
  for (const key in query) {
    if (Object.prototype.hasOwnProperty.call(query, key)) {
      const value = query[key];
      
      // Prevenir operadores peligrosos
      if (typeof key === 'string' && key.startsWith('$')) {
        continue; // Ignorar operadores en las claves
      }
      
      if (typeof value === 'object' && value !== null) {
        // Verificar que no contenga operadores peligrosos
        const dangerousOperators = ['$where', '$regex', '$code', '$function'];
        const hasDangerous = dangerousOperators.some(op => value.hasOwnProperty(op));
        
        if (!hasDangerous) {
          sanitized[key] = sanitizeMongoQuery(value);
        }
      } else if (typeof value === 'string') {
        sanitized[key] = sanitizeString(value);
      } else {
        sanitized[key] = value;
      }
    }
  }
  
  return sanitized;
}

/**
 * Valida y sanitiza datos de entrada de API
 */
export function validateAndSanitize(data, schema) {
  const sanitized = sanitizeObject(data);
  const errors = [];
  
  for (const field in schema) {
    const rules = schema[field];
    const value = sanitized[field];
    
    // Verificar requerido
    if (rules.required && (value === undefined || value === null || value === '')) {
      errors.push(`${field} es requerido`);
      continue;
    }
    
    // Si no es requerido y no está presente, continuar
    if (!rules.required && (value === undefined || value === null || value === '')) {
      continue;
    }
    
    // Validar tipo
    if (rules.type && typeof value !== rules.type) {
      errors.push(`${field} debe ser de tipo ${rules.type}`);
      continue;
    }
    
    // Validar función personalizada
    if (rules.validate && !rules.validate(value)) {
      errors.push(rules.message || `${field} no es válido`);
    }
    
    // Validar longitud
    if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) {
      errors.push(`${field} debe tener al menos ${rules.minLength} caracteres`);
    }
    
    if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
      errors.push(`${field} no puede tener más de ${rules.maxLength} caracteres`);
    }
    
    // Validar rango numérico
    if (rules.min !== undefined && typeof value === 'number' && value < rules.min) {
      errors.push(`${field} debe ser al menos ${rules.min}`);
    }
    
    if (rules.max !== undefined && typeof value === 'number' && value > rules.max) {
      errors.push(`${field} no puede ser mayor que ${rules.max}`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    data: sanitized,
  };
}

