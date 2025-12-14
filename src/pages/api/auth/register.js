import { connectToDatabase } from "../../../util/mongodb";
import bcrypt from "bcryptjs";
import { validateRegisterData, sanitizeObject, sanitizeMongoQuery } from "../../../util/validation";
import { registerRateLimiter } from "../../../util/rateLimiter";

// Aplicar rate limiting
const rateLimitHandler = registerRateLimiter();

export default async function handler(req, res) {
  // Aplicar rate limiting
  await new Promise((resolve) => {
    rateLimitHandler(req, res, resolve);
  });

  if (req.method !== "POST") {
    return res.status(405).json({ message: "Método no permitido" });
  }

  try {
    // Sanitizar y validar datos de entrada
    const sanitizedData = sanitizeObject(req.body);
    const { name, username, email, password, confirmPassword } = sanitizedData;

    // Validaciones mejoradas
    const validation = validateRegisterData(sanitizedData);
    if (!validation.isValid) {
      return res.status(400).json({ 
        message: validation.errors[0] || "Datos inválidos",
        errors: validation.errors 
      });
    }

    const { db } = await connectToDatabase();

    // Sanitizar query para prevenir inyección NoSQL
    const sanitizedUsername = sanitizeObject({ username }).username;
    const sanitizedEmail = sanitizeObject({ email }).email;
    
    // Verificar si el usuario ya existe (con query sanitizado)
    const query = sanitizeMongoQuery({
      $or: [{ username: sanitizedUsername }, { email: sanitizedEmail }],
    });
    
    const existingUser = await db.collection("users").findOne(query);

    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ message: "El nombre de usuario ya está en uso" });
      }
      if (existingUser.email === email) {
        return res.status(400).json({ message: "El correo electrónico ya está en uso" });
      }
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear el usuario (datos ya sanitizados)
    const result = await db.collection("users").insertOne({
      name: sanitizedData.name,
      username: sanitizedUsername,
      email: sanitizedEmail,
      password: hashedPassword,
      createdAt: new Date(),
    });

    return res.status(201).json({
      message: "Usuario registrado exitosamente",
      userId: result.insertedId,
    });
  } catch (error) {
    console.error("Error en registro:", error);
    
    // Mensajes de error más específicos
    if (error.message && error.message.includes("authentication failed")) {
      return res.status(500).json({ 
        message: "Error de conexión con la base de datos. Verifica las credenciales de MongoDB." 
      });
    }
    
    if (error.message && error.message.includes("ENOTFOUND") || error.message.includes("ECONNREFUSED")) {
      return res.status(500).json({ 
        message: "No se pudo conectar a la base de datos. Verifica tu conexión a internet y la configuración de MongoDB." 
      });
    }
    
    return res.status(500).json({ 
      message: error.message || "Error interno del servidor",
      error: process.env.NODE_ENV === "development" ? error.message : undefined
    });
  }
}

