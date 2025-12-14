/**
 * Middleware de autenticación y autorización
 */

import { getSession } from "next-auth/client";

/**
 * Verifica que el usuario esté autenticado
 */
export async function requireAuth(req, res) {
  const session = await getSession({ req });
  
  if (!session || !session.user) {
    return {
      authorized: false,
      status: 401,
      message: "No autorizado. Debes iniciar sesión.",
    };
  }
  
  return {
    authorized: true,
    session,
  };
}

/**
 * Verifica que el usuario sea administrador
 */
export async function requireAdmin(req, res) {
  const authResult = await requireAuth(req, res);
  
  if (!authResult.authorized) {
    return authResult;
  }
  
  if (!authResult.session.admin) {
    return {
      authorized: false,
      status: 403,
      message: "Acceso denegado. Se requieren permisos de administrador.",
    };
  }
  
  return {
    authorized: true,
    session: authResult.session,
  };
}

/**
 * Verifica que el usuario sea el propietario del recurso o admin
 */
export async function requireOwnerOrAdmin(req, res, resourceUserId) {
  const authResult = await requireAuth(req, res);
  
  if (!authResult.authorized) {
    return authResult;
  }
  
  const session = authResult.session;
  
  // Si es admin, permitir acceso
  if (session.admin) {
    return {
      authorized: true,
      session,
    };
  }
  
  // Verificar que sea el propietario
  const userId = session.user.id || session.user.email;
  if (userId !== resourceUserId && session.user.email !== resourceUserId) {
    return {
      authorized: false,
      status: 403,
      message: "Acceso denegado. No tienes permiso para acceder a este recurso.",
    };
  }
  
  return {
    authorized: true,
    session,
  };
}

/**
 * Wrapper para APIs que requieren autenticación
 */
export function withAuth(handler) {
  return async (req, res) => {
    const authResult = await requireAuth(req, res);
    
    if (!authResult.authorized) {
      return res.status(authResult.status).json({ message: authResult.message });
    }
    
    req.session = authResult.session;
    return handler(req, res);
  };
}

/**
 * Wrapper para APIs que requieren admin
 */
export function withAdmin(handler) {
  return async (req, res) => {
    const authResult = await requireAdmin(req, res);
    
    if (!authResult.authorized) {
      return res.status(authResult.status).json({ message: authResult.message });
    }
    
    req.session = authResult.session;
    return handler(req, res);
  };
}

/**
 * Wrapper para APIs que requieren owner o admin
 */
export function withOwnerOrAdmin(handler, getResourceUserId) {
  return async (req, res) => {
    const resourceUserId = getResourceUserId ? getResourceUserId(req) : req.body.userId || req.query.userId;
    const authResult = await requireOwnerOrAdmin(req, res, resourceUserId);
    
    if (!authResult.authorized) {
      return res.status(authResult.status).json({ message: authResult.message });
    }
    
    req.session = authResult.session;
    return handler(req, res);
  };
}

