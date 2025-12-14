import { connectToDatabase } from "../../../util/mongodb";
import { withAdmin } from "../../../middleware/auth";
import { validateAndConvertObjectId } from "../../../util/security";
import { checkRateLimit } from "../../../util/rateLimiter";
import { setSecurityHeaders } from "../../../util/security";

async function handler(req, res) {
    // Aplicar rate limiting
    const canContinue = await checkRateLimit(req, res);
    if (!canContinue) {
        return; // Ya se envió respuesta 429
    }

    // Agregar headers de seguridad
    setSecurityHeaders(res);

    if (req.method !== "DELETE" && req.method !== "POST") {
        return res.status(405).json({ message: "Método no permitido" });
    }

    try {
        const _id = req.method === "DELETE" ? req.body._id : req.body._id;

        if (!_id) {
            return res.status(400).json({ message: "ID de pedido requerido" });
        }

        // Validar ObjectId
        let orderId;
        try {
            orderId = validateAndConvertObjectId(_id, "ID del pedido");
        } catch (error) {
            return res.status(400).json({ message: error.message });
        }

        const { db } = await connectToDatabase();

        // Verificar que el pedido existe
        const order = await db.collection("orders").findOne({ _id: orderId });

        if (!order) {
            return res.status(404).json({ message: "Pedido no encontrado" });
        }

        // Eliminar el pedido
        const result = await db.collection("orders").deleteOne({ _id: orderId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Pedido no encontrado" });
        }

        return res.status(200).json({ message: "Pedido eliminado exitosamente" });
    } catch (err) {
        console.error("Error eliminando pedido:", err);
        return res.status(500).json({ message: "Error interno del servidor" });
    }
}

export default withAdmin(handler);

