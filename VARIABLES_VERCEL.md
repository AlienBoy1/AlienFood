# 🔑 Variables de Entorno para Vercel

## Variables Requeridas

Copia y pega estas variables en Vercel (Settings → Environment Variables):

### 1. VAPID Keys (Para Notificaciones Push)

**Primero, genera las keys si no las tienes:**
```bash
npx web-push generate-vapid-keys
```

Luego agrega en Vercel:

```
VAPID_PUBLIC_KEY = [tu-clave-publica-completa]
VAPID_PRIVATE_KEY = [tu-clave-privada-completa]
```

**⚠️ IMPORTANTE:** 
- Copia las keys COMPLETAS (son strings largos)
- No dejes espacios al inicio o final
- Selecciona los 3 entornos: Production, Preview, Development

### 2. MongoDB (Si usas MongoDB)

```
MONGODB_URI = [tu-uri-de-mongodb]
```

Ejemplo: `mongodb+srv://usuario:password@cluster.mongodb.net/database?retryWrites=true&w=majority`

**Selecciona:** Production, Preview, Development

### 3. NextAuth (Para autenticación)

```
NEXTAUTH_URL = https://tu-proyecto.vercel.app
NEXTAUTH_SECRET = [genera-un-string-aleatorio]
```

**Para generar NEXTAUTH_SECRET:**
```bash
openssl rand -base64 32
```

O usa: https://generate-secret.vercel.app/32

**Selecciona:**
- `NEXTAUTH_URL`: Solo Production
- `NEXTAUTH_SECRET`: Production, Preview, Development

### 4. Stripe (Si usas Stripe)

```
STRIPE_PUBLIC_KEY = [tu-stripe-public-key]
STRIPE_SECRET_KEY = [tu-stripe-secret-key]
```

**Selecciona:** Production, Preview, Development

## 📝 Instrucciones Paso a Paso

1. **Después de hacer clic en "Crear" en Vercel:**
   - Espera a que Vercel detecte Next.js
   - Verás una pantalla de configuración

2. **Haz clic en "Environment Variables" o "Variables de Entorno"**

3. **Agrega cada variable:**
   - Key: `VAPID_PUBLIC_KEY`
   - Value: [pega tu clave pública completa]
   - Selecciona: ☑️ Production ☑️ Preview ☑️ Development
   - Haz clic en "Add" o "Agregar"

4. **Repite para cada variable de la lista**

5. **IMPORTANTE:** Después de agregar todas las variables, haz clic en "Deploy" o "Desplegar"

## ⚠️ Notas Importantes

- **NO** subas archivos `.env.local` a GitHub
- **SÍ** agrega todas las variables en Vercel
- Después de agregar variables, **redespliega** el proyecto
- La URL de tu proyecto será: `https://tu-proyecto.vercel.app`

## 🔄 Si ya desplegaste sin variables

1. Ve a tu proyecto en Vercel
2. Settings → Environment Variables
3. Agrega las variables faltantes
4. Ve a Deployments
5. Haz clic en los 3 puntos (⋯) del último despliegue
6. Selecciona "Redeploy"

