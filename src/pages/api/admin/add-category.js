import { connectToDatabase } from "../../../util/mongodb";
import { withAdmin } from "../../../middleware/auth";
import { validateCategoryData } from "../../../util/security";
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
        const validation = validateCategoryData(req.body);
        
        if (!validation.isValid) {
            return res.status(400).json({
                message: validation.errors[0] || "Datos inválidos",
                errors: validation.errors,
            });
        }

        const { db } = await connectToDatabase();
        
        // Verificar que la categoría no existe ya
        const existingCategory = await db.collection("categories").findOne({
            name: validation.data.name,
        });
        
        if (existingCategory) {
            return res.status(400).json({
                message: "La categoría ya existe",
            });
        }

        // Crear la categoría
        const category = {
            ...validation.data,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        const result = await db.collection("categories").insertOne(category);
        
        return res.status(201).json({
            message: "Categoría agregada exitosamente",
            categoryId: result.insertedId,
        });
    } catch (err) {
        console.error("Error agregando categoría:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
        });
    }
}

export default withAdmin(handler);
