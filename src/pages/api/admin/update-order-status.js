import { connectToDatabase } from "../../../util/mongodb";
import { withAdmin } from "../../../middleware/auth";
import { validateAndConvertObjectId, validateOrderStatus } from "../../../util/security";
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

    if (req.method !== "PUT" && req.method !== "POST") {
        return res.status(405).json({ message: "Método no permitido" });
    }

    try {
        const sanitized = sanitizeObject(req.body);
        const { status, _id } = sanitized;

        // Validar que se proporcionen los campos requeridos
        if (!status || !_id) {
            return res.status(400).json({
                message: "Estado e ID de pedido son requeridos",
            });
        }

        // Validar ObjectId
        let orderId;
        try {
            orderId = validateAndConvertObjectId(_id, "ID del pedido");
        } catch (error) {
            return res.status(400).json({ message: error.message });
        }

        // Validar estado
        if (!validateOrderStatus(status)) {
            return res.status(400).json({
                message: "Estado inválido. Estados permitidos: pending, processing, completed, cancelled",
            });
        }

        const { db } = await connectToDatabase();
        
        // Verificar que el pedido existe
        const order = await db.collection("orders").findOne({ _id: orderId });
        
        if (!order) {
            return res.status(404).json({
                message: "Pedido no encontrado",
            });
        }

        // Actualizar el estado del pedido
        const ord_status = { status, timestamp: new Date() };
        const order_status = {
            current: ord_status,
            info: [...(order.order_status?.info || []), ord_status],
        };

        const result = await db.collection("orders").updateOne(
            { _id: orderId },
            { $set: { order_status, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                message: "Pedido no encontrado",
            });
        }

        return res.status(200).json({
            message: "Estado del pedido actualizado exitosamente",
        });
    } catch (err) {
        console.error("Error actualizando estado del pedido:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
        });
    }
}

export default withAdmin(handler);
