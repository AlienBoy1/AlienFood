import { connectToDatabase } from "../../../util/mongodb";
import { getSession } from "next-auth/client";
import { configureWebPush } from "../../../util/vapid";
import webpush from "web-push";
import { withAuth } from "../../../middleware/auth";
import { validatePushSubscription } from "../../../util/security";
import { checkRateLimit } from "../../../util/rateLimiter";
import { setSecurityHeaders } from "../../../util/security";
import { sanitizeObject } from "../../../util/validation";

async function handler(req, res) {
    // Aplicar rate limiting
    const canContinue = await checkRateLimit(req, res);
    if (!canContinue) {
        return; // Ya se envió respuesta 429
    }

    // Agregar headers de seguridad
    setSecurityHeaders(res);

    if (req.method !== "POST") {
        return res.status(405).json({ message: "Método no permitido" });
    }

    try {
        const sanitized = sanitizeObject(req.body);
        let { subscription } = sanitized;

        if (!subscription) {
            return res.status(400).json({ message: "Suscripción requerida" });
        }

        // Normalizar la suscripción: puede venir en diferentes formatos
        if (subscription.getKey && typeof subscription.getKey === 'function') {
            // Si es un objeto PushSubscription real (no debería pasar desde el cliente, pero por si acaso)
            // En Node.js, usar Buffer en lugar de btoa
            try {
                const p256dhKey = subscription.getKey('p256dh');
                const authKey = subscription.getKey('auth');
                
                subscription = {
                    endpoint: subscription.endpoint,
                    keys: {
                        p256dh: Buffer.from(p256dhKey).toString('base64'),
                        auth: Buffer.from(authKey).toString('base64'),
                    },
                };
            } catch (e) {
                console.error('Error normalizando suscripción:', e);
                return res.status(400).json({ message: "Error procesando suscripción" });
            }
        }

        // Validar la suscripción usando la función de validación
        const validation = validatePushSubscription(subscription);
        if (!validation.valid) {
            console.error("Suscripción inválida recibida:", validation.error);
            return res.status(400).json({ message: validation.error });
        }

        const session = req.session; // Ya viene del middleware withAuth
        
        if (!session || !session.user || !session.user.email) {
            return res.status(401).json({ message: "No autorizado" });
        }
        
        console.debug("✅ Suscripción válida recibida para user:", session.user.email);
        console.debug("Subscription endpoint:", subscription.endpoint.substring(0, 50) + "...");

    const { db } = await connectToDatabase();

    // Guardar o actualizar la suscripción del usuario
    await db.collection("pushSubscriptions").updateOne(
      { userId: session.user.email },
      {
        $set: {
          subscription: subscription,
          userId: session.user.email,
          username: session.user.username,
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );

    // Después de guardar la suscripción, intentar enviar notificaciones pendientes
    try {
      configureWebPush();
      const pending = await db
        .collection("pendingNotifications")
        .find({ userId: session.user.email })
        .toArray();

      if (pending.length > 0) {
        console.debug(`Enviando ${pending.length} notificaciones pendientes a ${session.user.email}`);
        for (const p of pending) {
          try {
            await webpush.sendNotification(subscription, JSON.stringify(p.payload));
            // si se envió correctamente, borrarla
            await db.collection("pendingNotifications").deleteOne({ _id: p._id });
          } catch (e) {
            console.error("Error enviando notificación pendiente:", e);
            // Si la suscripción está inválida eliminarla
            if (e.statusCode === 410 || e.statusCode === 404) {
              await db.collection("pushSubscriptions").deleteOne({ userId: session.user.email });
            }
            // Si falla por otra razón, dejamos la notificación pendiente para reintentar luego
          }
        }
      }
    } catch (e) {
      console.error("Error procesando notificaciones pendientes:", e);
    }

        return res.status(200).json({ message: "Suscripción guardada exitosamente" });
    } catch (error) {
        console.error("Error guardando suscripción:", error);
        return res.status(500).json({ message: "Error interno del servidor" });
    }
}

export default withAuth(handler);


