# 🔧 Configuración de Variables de Entorno en Vercel - Paso a Paso

## ❌ Problemas Encontrados

1. **Usaste `MONGO_URI` pero el código espera `MONGODB_URI`** - Necesitas cambiar el nombre
2. **Faltan `NEXTAUTH_URL` y `NEXTAUTH_SECRET`** - NextAuth las requiere aunque no aparezcan explícitamente en el código

## ✅ Solución Completa

### Paso 1: Corregir la Variable de MongoDB

En Vercel, **elimina** `MONGO_URI` y **agrega** `MONGODB_URI` con el mismo valor:

```
MONGODB_URI = mongodb+srv://alien:alien@cluster0.xr01zqx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
```

**Selecciona:** ☑️ Production ☑️ Preview ☑️ Development

### Paso 2: Generar NEXTAUTH_SECRET

**Opción A: Usando PowerShell (Windows)**
```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

**Opción B: Usando Node.js (si tienes Node instalado)**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

**Opción C: Usar generador online**
Ve a: https://generate-secret.vercel.app/32

Copia el valor generado (será una cadena larga de caracteres).

### Paso 3: Obtener tu URL de Vercel

1. Ve a tu proyecto en Vercel
2. En la página principal del proyecto, verás tu URL de producción
3. Será algo como: `https://tu-proyecto.vercel.app`
4. **Si aún no has desplegado**, usa un nombre temporal como: `https://aaliieenfoodweeb.vercel.app` (o el nombre que Vercel te asignó)

### Paso 4: Agregar Variables en Vercel

Ve a **Settings → Environment Variables** y agrega estas variables:

#### Variable 1: NEXTAUTH_SECRET
- **Key:** `NEXTAUTH_SECRET`
- **Value:** [Pega el valor generado en el Paso 2]
- **Selecciona:** ☑️ Production ☑️ Preview ☑️ Development
- Haz clic en **Add**

#### Variable 2: NEXTAUTH_URL
- **Key:** `NEXTAUTH_URL`
- **Value:** `https://tu-proyecto.vercel.app` (reemplaza con tu URL real)
- **Selecciona:** ☑️ Production solamente
- Haz clic en **Add**

## 📋 Resumen de Todas las Variables

Asegúrate de tener estas variables configuradas en Vercel:

| Variable | Valor | Entornos |
|----------|-------|----------|
| `VAPID_PUBLIC_KEY` | `BLA2PGnRwH7V-QycEZagHWm1TLyzkzc53CgTLLgCTflZUzySU4s1uxq6V6z6dSDWE-PI7HFURsSwfiGLxkpp6pg` | Production, Preview, Development |
| `VAPID_PRIVATE_KEY` | `jHwlbRFeYV1AcU2q8Ct7QD6TUBBGmPzmFKbQhYgHrsk` | Production, Preview, Development |
| `MONGODB_URI` | `mongodb+srv://alien:alien@cluster0.xr01zqx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0` | Production, Preview, Development |
| `MONGODB_DB` | `zinger` | Production, Preview, Development |
| `NEXTAUTH_SECRET` | [Valor generado] | Production, Preview, Development |
| `NEXTAUTH_URL` | `https://tu-proyecto.vercel.app` | Production solamente |

## ⚠️ IMPORTANTE

1. **Elimina `MONGO_URI`** si la tienes (el código usa `MONGODB_URI`)
2. **Después de agregar todas las variables**, ve a **Deployments**
3. Haz clic en los **3 puntos (⋯)** del último despliegue
4. Selecciona **"Redeploy"** para aplicar los cambios

## 🔍 Verificación

Después del redespliegue, verifica que:

1. El build se complete exitosamente
2. Puedas acceder a tu aplicación en la URL de Vercel
3. El login funcione correctamente
4. Las notificaciones push funcionen (requiere HTTPS, que Vercel proporciona automáticamente)

## 📝 Nota sobre NEXTAUTH_URL

- En **producción**, usa la URL completa de tu proyecto en Vercel
- En **desarrollo local**, NextAuth detecta automáticamente `http://localhost:3000`
- Vercel también proporciona `VERCEL_URL` automáticamente, pero es mejor definir `NEXTAUTH_URL` explícitamente para evitar problemas

