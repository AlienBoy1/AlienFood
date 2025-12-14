import { getSession } from "next-auth/client";
import { connectToDatabase } from "../../../util/mongodb";
import { ObjectId } from "bson";
import bcrypt from "bcryptjs";
import { validateProfileUpdateData, sanitizeObject, sanitizeMongoQuery, validateEmail, validateUsername, validateName, sanitizeString } from "../../../util/validation";
import { withAuth } from "../../../middleware/auth";
import { checkRateLimit } from "../../../util/rateLimiter";

async function handler(req, res) {
  // Aplicar rate limiting
  const canContinue = await checkRateLimit(req, res);
  if (!canContinue) {
    return; // Ya se envió respuesta 429
  }

  if (req.method !== "PUT") {
    return res.status(405).json({ message: "Método no permitido" });
  }

  try {
    const session = req.session; // Ya viene del middleware withAuth

    // Sanitizar y validar datos de entrada
    const sanitizedData = sanitizeObject(req.body);
    const { name, username, email, password, image } = sanitizedData;

    // Verificar que al menos un campo esté presente
    if (!name && !username && !email && !password && !image) {
      return res.status(400).json({ message: "Al menos un campo debe ser actualizado" });
    }

    // Validar datos actualizados
    const validation = validateProfileUpdateData(sanitizedData);
    if (!validation.isValid) {
      return res.status(400).json({ 
        message: validation.errors[0] || "Datos inválidos",
        errors: validation.errors 
      });
    }

    const { db } = await connectToDatabase();

    // Obtener el usuario actual
    const user = await db.collection("users").findOne({ email: session.user.email });

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const updateData = {};

    if (name && validateName(name)) updateData.name = name;
    if (username && validateUsername(username)) updateData.username = username;
    // Validar que image sea una URL válida o un string seguro
    if (image && typeof image === 'string' && image.length <= 500) {
      updateData.image = sanitizeString(image, 500);
    }

    // Si se cambia el email, verificar que no esté en uso
    if (email && email !== user.email) {
      if (!validateEmail(email)) {
        return res.status(400).json({ message: "El correo electrónico no es válido" });
      }
      
      const sanitizedEmail = sanitizeObject({ email }).email;
      const query = sanitizeMongoQuery({ email: sanitizedEmail });
      const existingUser = await db.collection("users").findOne(query);
      
      if (existingUser) {
        return res.status(400).json({ message: "El correo electrónico ya está en uso" });
      }
      updateData.email = sanitizedEmail;

      // Si el usuario es admin, actualizar la referencia en admins
      const adminExists = await db.collection("admins").findOne({ user: user.email });
      if (adminExists) {
        await db.collection("admins").updateOne(
          { user: user.email },
          { $set: { user: email } }
        );
      }
    }

    // Si se cambia la contraseña
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ message: "La contraseña debe tener al menos 6 caracteres" });
      }
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Verificar si el username ya está en uso por otro usuario
    if (username && username !== user.username) {
      const sanitizedUsername = sanitizeObject({ username }).username;
      const query = sanitizeMongoQuery({
        _id: { $ne: user._id },
        username: sanitizedUsername,
      });
      
      const existingUser = await db.collection("users").findOne(query);

      if (existingUser) {
        return res.status(400).json({ message: "El nombre de usuario ya está en uso" });
      }
    }

    updateData.updatedAt = new Date();

    // Actualizar el usuario
    const result = await db.collection("users").updateOne(
      { _id: user._id },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    return res.status(200).json({
      message: "Perfil actualizado exitosamente",
      user: {
        name: updateData.name || user.name,
        username: updateData.username || user.username,
        email: updateData.email || user.email,
        image: updateData.image || user.image,
      },
    });
  } catch (error) {
    console.error("Error actualizando perfil:", error);
    return res.status(500).json({ message: "Error interno del servidor" });
  }
}

export default withAuth(handler);

