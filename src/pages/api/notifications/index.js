import { connectToDatabase } from "../../../util/mongodb";
import { withAuth } from "../../../middleware/auth";
import { validateAndConvertObjectId, setSecurityHeaders } from "../../../util/security";
import { checkRateLimit } from "../../../util/rateLimiter";
import { ObjectId } from "bson";

// GET - Obtener notificaciones del usuario
// POST - Marcar notificación como leída
async function handler(req, res) {
    // Aplicar rate limiting
    const canContinue = await checkRateLimit(req, res);
    if (!canContinue) {
        return; // Ya se envió respuesta 429
    }

    // Agregar headers de seguridad
    setSecurityHeaders(res);

    try {
        const session = req.session; // Ya viene del middleware withAuth
        
        if (!session || !session.user || !session.user.email) {
            return res.status(401).json({ message: "No autorizado" });
        }
        
        const { db } = await connectToDatabase();
        const userId = session.user.email;

    if (req.method === "GET") {
      // Obtener todas las notificaciones del usuario, ordenadas por fecha (más recientes primero)
      const notifications = await db
        .collection("notifications")
        .find({ userId })
        .sort({ createdAt: -1 })
        .limit(100) // Limitar a las últimas 100 notificaciones
        .toArray();

      return res.status(200).json(notifications);
    }

        if (req.method === "POST") {
            // Marcar notificación como leída
            const { notificationId, read } = req.body;

            if (!notificationId) {
                return res.status(400).json({ message: "ID de notificación requerido" });
            }

            // Validar ObjectId
            let notifId;
            try {
                notifId = validateAndConvertObjectId(notificationId, "ID de notificación");
            } catch (error) {
                return res.status(400).json({ message: error.message });
            }

            const updateData = {
                read: read !== undefined ? read : true,
                readAt: read !== false ? new Date() : null,
            };

            const result = await db.collection("notifications").updateOne(
                { _id: notifId, userId },
                { $set: updateData }
            );

      if (result.matchedCount === 0) {
        return res.status(404).json({ message: "Notificación no encontrada" });
      }

      return res.status(200).json({ message: "Notificación actualizada" });
    }

    if (req.method === "PUT") {
      // Marcar todas las notificaciones como leídas
      const result = await db.collection("notifications").updateMany(
        { userId, read: false },
        { $set: { read: true, readAt: new Date() } }
      );

      return res.status(200).json({ 
        message: "Todas las notificaciones marcadas como leídas",
        updated: result.modifiedCount 
      });
    }

        if (req.method === "DELETE") {
            // Eliminar notificación
            const { notificationId } = req.body;

            if (!notificationId) {
                return res.status(400).json({ message: "ID de notificación requerido" });
            }

            // Validar ObjectId
            let notifId;
            try {
                notifId = validateAndConvertObjectId(notificationId, "ID de notificación");
            } catch (error) {
                return res.status(400).json({ message: error.message });
            }

            const result = await db.collection("notifications").deleteOne({
                _id: notifId,
                userId,
            });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Notificación no encontrada" });
      }

      return res.status(200).json({ message: "Notificación eliminada" });
    }

        return res.status(405).json({ message: "Método no permitido" });
    } catch (error) {
        console.error("Error en API de notificaciones:", error);
        return res.status(500).json({ message: "Error interno del servidor" });
    }
}

export default withAuth(handler);

