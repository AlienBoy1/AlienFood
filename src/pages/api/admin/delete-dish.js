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
        // Validar ObjectId
        let dishId;
        try {
            const id = req.method === "DELETE" ? req.body._id : req.body._id;
            dishId = validateAndConvertObjectId(id, "ID del producto");
        } catch (error) {
            return res.status(400).json({ message: error.message });
        }

        const { db } = await connectToDatabase();
        
        // Verificar que el producto existe
        const dish = await db.collection("dishes").findOne({ _id: dishId });
        
        if (!dish) {
            return res.status(404).json({
                message: "Producto no encontrado",
            });
        }

        // Eliminar el producto
        const result = await db.collection("dishes").deleteOne({ _id: dishId });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                message: "Producto no encontrado",
            });
        }

        return res.status(200).json({
            message: "Producto eliminado exitosamente",
        });
    } catch (err) {
        console.error("Error eliminando producto:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
        });
    }
}

export default withAdmin(handler);
