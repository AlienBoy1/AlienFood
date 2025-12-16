import { getSession } from "next-auth/client";
import { connectToDatabase } from "../../../util/mongodb";
import { withAdmin } from "../../../middleware/auth";
import { validateDishData } from "../../../util/security";
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

    if (req.method !== "POST") {
        return res.status(405).json({ message: "Método no permitido" });
    }

    try {
        // Validar y sanitizar datos
        const validation = validateDishData(req.body);
        
        if (!validation.isValid) {
            return res.status(400).json({
                message: validation.errors[0] || "Datos inválidos",
                errors: validation.errors,
            });
        }

        const { db } = await connectToDatabase();
        
        // Verificar que la categoría existe
        const category = await db.collection("categories").findOne({
            name: validation.data.category,
        });
        
        if (!category) {
            return res.status(400).json({
                message: "La categoría especificada no existe",
            });
        }

        // Crear el producto con datos validados
        const dish = {
            ...validation.data,
            price: validation.data.price,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        const result = await db.collection("dishes").insertOne(dish);
        
        return res.status(201).json({
            message: "Producto agregado exitosamente",
            dishId: result.insertedId,
        });
    } catch (err) {
        console.error("Error agregando producto:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
        });
    }
}

export default withAdmin(handler);
