import { getSession } from "next-auth/client";
import { connectToDatabase } from "../../../util/mongodb";
import { withAdmin } from "../../../middleware/auth";
import { validateDishData, validateAndConvertObjectId } from "../../../util/security";
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

    if (req.method !== "PUT" && req.method !== "POST") {
        return res.status(405).json({ message: "Método no permitido" });
    }

    try {
        // Validar ObjectId
        let dishId;
        try {
            dishId = validateAndConvertObjectId(req.body._id, "ID del producto");
        } catch (error) {
            return res.status(400).json({ message: error.message });
        }

        // Validar y sanitizar datos
        const validation = validateDishData(req.body);
        
        if (!validation.isValid) {
            return res.status(400).json({
                message: validation.errors[0] || "Datos inválidos",
                errors: validation.errors,
            });
        }

        const { db } = await connectToDatabase();
        
        // Verificar que el producto existe
        const existingDish = await db.collection("dishes").findOne({ _id: dishId });
        
        if (!existingDish) {
            return res.status(404).json({
                message: "Producto no encontrado",
            });
        }

        // Verificar que la categoría existe
        const category = await db.collection("categories").findOne({
            name: validation.data.category,
        });
        
        if (!category) {
            return res.status(400).json({
                message: "La categoría especificada no existe",
            });
        }

        // Actualizar el producto
        const updateData = {
            ...validation.data,
            updatedAt: new Date(),
        };

        const result = await db.collection("dishes").updateOne(
            { _id: dishId },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                message: "Producto no encontrado",
            });
        }

        return res.status(200).json({
            message: "Producto actualizado exitosamente",
        });
    } catch (err) {
        console.error("Error actualizando producto:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
        });
    }
}

export default withAdmin(handler);
