# Seguridad Implementada en la Aplicación

## Resumen de Mejoras de Seguridad

Se ha implementado un sistema completo de seguridad en toda la aplicación para proteger contra vulnerabilidades comunes y garantizar la privacidad y seguridad de los datos.

## 1. Validación y Sanitización de Datos

### ✅ Implementado en:
- **APIs de Admin:**
  - `/api/admin/users.js` - Validación completa de usuarios
  - `/api/admin/add-dish.js` - Validación de platillos
  - `/api/admin/update-dish.js` - Validación de actualizaciones
  - `/api/admin/delete-dish.js` - Validación de ObjectId
  - `/api/admin/add-category.js` - Validación de categorías
  - `/api/admin/send-notification.js` - Validación de notificaciones
  - `/api/admin/update-order-status.js` - Validación de estados
  - `/api/admin/delete-order.js` - Validación de ObjectId

- **APIs de Usuario:**
  - `/api/auth/register.js` - Validación de registro
  - `/api/auth/[...nextauth].js` - Validación de credenciales
  - `/api/profile/update.js` - Validación de perfil
  - `/api/push/subscribe.js` - Validación de suscripciones push
  - `/api/notifications/save.js` - Validación de notificaciones
  - `/api/notifications/index.js` - Validación de ObjectId

### Funciones de Validación:
- `validateEmail()` - Valida formato de email
- `validateUsername()` - Valida formato de username
- `validatePassword()` - Valida fortaleza de contraseña
- `validateName()` - Valida nombres
- `validateObjectId()` - Valida ObjectId de MongoDB
- `validateDishData()` - Valida datos de platillos
- `validateCategoryData()` - Valida datos de categorías
- `validateNotificationData()` - Valida datos de notificaciones
- `validatePushSubscription()` - Valida suscripciones push
- `validateOrderStatus()` - Valida estados de pedidos

### Funciones de Sanitización:
- `sanitizeString()` - Elimina caracteres peligrosos
- `sanitizeObject()` - Sanitiza objetos completos
- `sanitizeMongoQuery()` - Previene inyección NoSQL

## 2. Rate Limiting

### ✅ Implementado en:
- Todas las APIs críticas tienen rate limiting configurado
- Rate limiters específicos:
  - `loginRateLimiter` - 5 intentos cada 15 minutos
  - `registerRateLimiter` - 3 registros por hora
  - `apiRateLimiter` - 100 requests cada 15 minutos

### Headers de Rate Limit:
- `X-RateLimit-Limit` - Límite máximo
- `X-RateLimit-Remaining` - Requests restantes
- `X-RateLimit-Reset` - Tiempo de reset
- `Retry-After` - Tiempo de espera cuando se excede el límite

## 3. Headers de Seguridad

### ✅ Implementado en:
- Headers globales en `next.config.js`
- Headers por API usando `setSecurityHeaders()`

### Headers Configurados:
- `X-Content-Type-Options: nosniff` - Previene MIME sniffing
- `X-Frame-Options: DENY` - Previene clickjacking
- `X-XSS-Protection: 1; mode=block` - Protección XSS
- `Referrer-Policy: strict-origin-when-cross-origin` - Control de referrer
- `Permissions-Policy` - Controla permisos del navegador
- `Strict-Transport-Security` - Fuerza HTTPS

## 4. Protección de Rutas

### ✅ Middleware de Autenticación:
- `withAuth()` - Requiere autenticación
- `withAdmin()` - Requiere permisos de administrador
- `withOwnerOrAdmin()` - Requiere ser propietario o admin

### Implementado en:
- Todas las APIs de admin usan `withAdmin()`
- APIs de usuario usan `withAuth()`
- Validación de sesión en todas las rutas protegidas

## 5. Protección contra Inyección

### ✅ NoSQL Injection:
- `sanitizeMongoQuery()` - Sanitiza queries de MongoDB
- Validación de ObjectId antes de usar en queries
- Prevención de operadores peligrosos (`$where`, `$regex`, `$code`, `$function`)

### ✅ XSS (Cross-Site Scripting):
- Sanitización de strings de entrada
- Eliminación de tags HTML peligrosos
- Eliminación de event handlers (`onclick`, `onerror`, etc.)
- Eliminación de `javascript:` en URLs

### ✅ SQL Injection:
- No aplicable (usamos MongoDB)
- Pero se previene inyección NoSQL equivalente

## 6. Validación de ObjectId

### ✅ Implementado:
- Función `validateAndConvertObjectId()` que:
  - Valida formato de ObjectId
  - Convierte a ObjectId de MongoDB
  - Proporciona mensajes de error claros

### Usado en:
- Todas las APIs que reciben IDs de MongoDB
- Validación antes de hacer queries
- Prevención de errores y ataques

## 7. Validación de Contraseñas

### ✅ Requisitos:
- Mínimo 8 caracteres
- Al menos una mayúscula
- Al menos una minúscula
- Al menos un número
- Máximo 128 caracteres

### Implementado en:
- Registro de usuarios
- Actualización de perfil
- Creación de usuarios por admin

## 8. Protección de Sesiones

### ✅ NextAuth.js Configurado:
- Cookies seguras en producción
- `httpOnly: true` - Previene acceso desde JavaScript
- `secure: true` en producción - Solo HTTPS
- `sameSite: 'lax'` - Protección CSRF
- `maxAge: 30 días` - Expiración de sesión

## 9. Validación de Datos de Entrada

### ✅ Validaciones Específicas:

**Platillos:**
- Título: 3-100 caracteres
- Categoría: 2-50 caracteres
- Descripción: máximo 1000 caracteres
- Precio: número positivo, máximo 1,000,000
- Imagen: URL válida o ruta relativa

**Categorías:**
- Nombre: 2-50 caracteres
- Verificación de duplicados

**Notificaciones:**
- Título: 3-100 caracteres
- Mensaje: 3-500 caracteres
- Validación de userId

**Suscripciones Push:**
- Validación de endpoint (URL válida)
- Validación de claves (p256dh, auth)
- Estructura completa de suscripción

## 10. Manejo de Errores

### ✅ Implementado:
- Mensajes de error genéricos (no revelan información sensible)
- Logging de errores en servidor
- Códigos de estado HTTP apropiados
- Validación antes de operaciones de base de datos

## 11. Protección de Datos Sensibles

### ✅ Implementado:
- Contraseñas hasheadas con bcrypt (10 rounds)
- No se devuelven contraseñas en respuestas
- Validación de permisos antes de acceder a datos
- Usuarios solo pueden acceder a sus propios datos (excepto admins)

## 12. Rate Limiting por IP

### ✅ Implementado:
- Identificación de IP desde headers:
  - `x-forwarded-for`
  - `x-real-ip`
  - `connection.remoteAddress`
- Límites diferentes por tipo de endpoint
- Limpieza automática de entradas expiradas

## Archivos Creados/Modificados

### Nuevos Archivos:
- `src/util/security.js` - Utilidades de seguridad
- `SEGURIDAD_IMPLEMENTADA.md` - Este documento

### Archivos Modificados:
- `src/pages/api/admin/*` - Todas las APIs de admin
- `src/pages/api/auth/[...nextauth].js` - Validación de credenciales
- `src/pages/api/push/subscribe.js` - Validación de suscripciones
- `src/pages/api/notifications/*` - Validación de notificaciones
- `next.config.js` - Headers de seguridad globales

## Recomendaciones Adicionales

1. **HTTPS Obligatorio:** Asegúrate de que la aplicación siempre use HTTPS en producción
2. **Variables de Entorno:** No commits de `.env.local` con datos sensibles
3. **Logging:** Considera usar un servicio de logging para producción
4. **Monitoreo:** Implementa monitoreo de intentos de ataque
5. **Backup:** Asegura backups regulares de la base de datos
6. **Actualizaciones:** Mantén las dependencias actualizadas

## Próximos Pasos Sugeridos

1. Implementar CAPTCHA en registro y login
2. Agregar 2FA (autenticación de dos factores)
3. Implementar logging de auditoría
4. Agregar validación de CSRF tokens
5. Implementar Content Security Policy más estricta

