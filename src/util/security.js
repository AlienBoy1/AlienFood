/**
 * Utilidades de seguridad adicionales
 */

import { ObjectId } from "bson";
import { validateObjectId, sanitizeString, sanitizeObject } from "./validation";

/**
 * Valida y convierte un string a ObjectId
 */
export function validateAndConvertObjectId(id, fieldName = "ID") {
  if (!id) {
    throw new Error(`${fieldName} es requerido`);
  }
  
  if (!validateObjectId(id)) {
    throw new Error(`${fieldName} no es válido`);
  }
  
  try {
    return ObjectId(id);
  } catch (error) {
    throw new Error(`${fieldName} no es un ObjectId válido`);
  }
}

/**
 * Valida que un precio sea válido
 */
export function validatePrice(price) {
  const numPrice = typeof price === 'string' ? parseFloat(price) : price;
  
  if (isNaN(numPrice) || !isFinite(numPrice)) {
    return { valid: false, error: "El precio debe ser un número válido" };
  }
  
  if (numPrice < 0) {
    return { valid: false, error: "El precio no puede ser negativo" };
  }
  
  if (numPrice > 1000000) {
    return { valid: false, error: "El precio es demasiado alto" };
  }
  
  return { valid: true, value: Math.round(numPrice * 100) / 100 }; // Redondear a 2 decimales
}

/**
 * Valida datos de un platillo
 */
export function validateDishData(data) {
  const errors = [];
  const sanitized = sanitizeObject(data);
  
  // Validar título
  if (!sanitized.title || typeof sanitized.title !== 'string') {
    errors.push("El título es requerido");
  } else if (sanitized.title.trim().length < 3) {
    errors.push("El título debe tener al menos 3 caracteres");
  } else if (sanitized.title.trim().length > 100) {
    errors.push("El título no puede tener más de 100 caracteres");
  }
  
  // Validar categoría
  if (!sanitized.category || typeof sanitized.category !== 'string') {
    errors.push("La categoría es requerida");
  } else if (sanitized.category.trim().length < 2) {
    errors.push("La categoría debe tener al menos 2 caracteres");
  } else if (sanitized.category.trim().length > 50) {
    errors.push("La categoría no puede tener más de 50 caracteres");
  }
  
  // Validar descripción
  if (sanitized.description && typeof sanitized.description === 'string') {
    if (sanitized.description.length > 1000) {
      errors.push("La descripción no puede tener más de 1000 caracteres");
    }
  }
  
  // Validar precio
  if (sanitized.price === undefined || sanitized.price === null) {
    errors.push("El precio es requerido");
  } else {
    const priceValidation = validatePrice(sanitized.price);
    if (!priceValidation.valid) {
      errors.push(priceValidation.error);
    }
  }
  
  // Validar imagen (opcional pero debe ser URL válida si está presente)
  if (sanitized.image && typeof sanitized.image === 'string') {
    if (sanitized.image.length > 500) {
      errors.push("La URL de la imagen es demasiado larga");
    }
    // Validar que sea una URL válida
    try {
      new URL(sanitized.image);
    } catch (e) {
      // Si no es una URL completa, verificar que sea una ruta relativa válida
      if (!sanitized.image.startsWith('/') && !sanitized.image.startsWith('./')) {
        errors.push("La imagen debe ser una URL válida o una ruta relativa");
      }
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    data: {
      title: sanitized.title?.trim(),
      category: sanitized.category?.trim(),
      description: sanitized.description?.trim() || "",
      price: sanitized.price !== undefined ? (typeof sanitized.price === 'number' ? sanitized.price : parseFloat(sanitized.price)) : null,
      image: sanitized.image?.trim() || "",
    },
  };
}

/**
 * Valida datos de una categoría
 */
export function validateCategoryData(data) {
  const errors = [];
  const sanitized = sanitizeObject(data);
  
  if (!sanitized.name || typeof sanitized.name !== 'string') {
    errors.push("El nombre de la categoría es requerido");
  } else if (sanitized.name.trim().length < 2) {
    errors.push("El nombre de la categoría debe tener al menos 2 caracteres");
  } else if (sanitized.name.trim().length > 50) {
    errors.push("El nombre de la categoría no puede tener más de 50 caracteres");
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    data: {
      name: sanitized.name?.trim(),
    },
  };
}

/**
 * Valida datos de notificación
 */
export function validateNotificationData(data) {
  const errors = [];
  const sanitized = sanitizeObject(data);
  
  if (!sanitized.title || typeof sanitized.title !== 'string') {
    errors.push("El título es requerido");
  } else if (sanitized.title.trim().length < 3) {
    errors.push("El título debe tener al menos 3 caracteres");
  } else if (sanitized.title.trim().length > 100) {
    errors.push("El título no puede tener más de 100 caracteres");
  }
  
  if (!sanitized.message || typeof sanitized.message !== 'string') {
    errors.push("El mensaje es requerido");
  } else if (sanitized.message.trim().length < 3) {
    errors.push("El mensaje debe tener al menos 3 caracteres");
  } else if (sanitized.message.trim().length > 500) {
    errors.push("El mensaje no puede tener más de 500 caracteres");
  }
  
  // Validar userId si está presente
  if (sanitized.userId && sanitized.userId !== "all") {
    if (typeof sanitized.userId !== 'string') {
      errors.push("El ID de usuario debe ser un string");
    } else if (!validateObjectId(sanitized.userId) && sanitized.userId.length > 100) {
      errors.push("El ID de usuario no es válido");
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    data: {
      title: sanitized.title?.trim(),
      message: sanitized.message?.trim(),
      userId: sanitized.userId || "all",
    },
  };
}

/**
 * Valida datos de suscripción push
 */
export function validatePushSubscription(subscription) {
  if (!subscription || typeof subscription !== 'object') {
    return { valid: false, error: "La suscripción es requerida" };
  }
  
  if (!subscription.endpoint || typeof subscription.endpoint !== 'string') {
    return { valid: false, error: "El endpoint de la suscripción es requerido" };
  }
  
  if (!subscription.keys || typeof subscription.keys !== 'object') {
    return { valid: false, error: "Las claves de la suscripción son requeridas" };
  }
  
  if (!subscription.keys.p256dh || typeof subscription.keys.p256dh !== 'string') {
    return { valid: false, error: "La clave p256dh es requerida" };
  }
  
  if (!subscription.keys.auth || typeof subscription.keys.auth !== 'string') {
    return { valid: false, error: "La clave auth es requerida" };
  }
  
  // Validar que el endpoint sea una URL válida
  try {
    new URL(subscription.endpoint);
  } catch (e) {
    return { valid: false, error: "El endpoint no es una URL válida" };
  }
  
  return { valid: true };
}

/**
 * Headers de seguridad
 */
export function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Solo agregar CSP en producción si es necesario
  if (process.env.NODE_ENV === 'production') {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:;"
    );
  }
}

/**
 * Valida estado de orden
 */
export function validateOrderStatus(status) {
  const validStatuses = ['pending', 'processing', 'completed', 'cancelled'];
  return validStatuses.includes(status);
}

