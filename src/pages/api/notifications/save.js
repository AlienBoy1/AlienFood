import { connectToDatabase } from "../../../util/mongodb";
import { getSession } from "next-auth/client";
import { withAuth } from "../../../middleware/auth";
import { checkRateLimit } from "../../../util/rateLimiter";
import { setSecurityHeaders } from "../../../util/security";
import { sanitizeObject, sanitizeString } from "../../../util/validation";

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
        // Sanitizar datos de entrada
        const sanitized = sanitizeObject(req.body);
        let { userId, title, body, icon, data, tag } = sanitized;

        // Intentar obtener userId de la sesión si no se proporciona
        const session = req.session; // Ya viene del middleware withAuth
        let targetUserId = userId || session?.user?.email;

        // Validar datos requeridos
        if (!targetUserId) {
            return res.status(400).json({ message: "userId es requerido" });
        }

        if (!title || typeof title !== 'string' || title.trim().length < 1) {
            return res.status(400).json({ message: "title es requerido y debe ser un string válido" });
        }

        if (!body || typeof body !== 'string' || body.trim().length < 1) {
            return res.status(400).json({ message: "body es requerido y debe ser un string válido" });
        }

        // Sanitizar y validar longitud
        title = sanitizeString(title, 100);
        body = sanitizeString(body, 500);
        icon = icon ? sanitizeString(icon, 500) : "/img/favicons/android-chrome-192x192.png";
        tag = tag ? sanitizeString(tag, 100) : `notification-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        const { db } = await connectToDatabase();

        // Verificar si ya existe una notificación con el mismo tag para evitar duplicados
        if (tag) {
            const existing = await db.collection("notifications").findOne({
                userId: targetUserId,
                tag: tag,
            });

            if (existing) {
                // Si ya existe, no crear duplicado
                return res.status(200).json({
                    message: "Notificación ya existe",
                    notificationId: existing._id,
                });
            }
        }

        // Guardar la notificación en la base de datos
        const notification = {
            userId: targetUserId,
            title,
            body,
            icon,
            data: data && typeof data === 'object' ? data : { url: "/" },
            tag,
            read: false,
            createdAt: new Date(),
        };

        const result = await db.collection("notifications").insertOne(notification);

        console.log(`Notificación guardada para ${targetUserId}:`, title);

        return res.status(201).json({
            message: "Notificación guardada",
            notificationId: result.insertedId,
        });
    } catch (error) {
        console.error("Error guardando notificación:", error);
        return res.status(500).json({ message: "Error interno del servidor" });
    }
}

export default withAuth(handler);

