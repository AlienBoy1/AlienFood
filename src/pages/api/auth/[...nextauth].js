import NextAuth from "next-auth";
import Providers from "next-auth/providers";
import { connectToDatabase } from "../../../util/mongodb";
import bcrypt from "bcryptjs";

export default NextAuth({
  providers: [
    Providers.Credentials({
      name: "Credentials",
      credentials: {
        username: { label: "Usuario", type: "text" },
        password: { label: "Contraseña", type: "password" },
      },
      async authorize(credentials) {
        try {
          // Validar y sanitizar credenciales
          if (!credentials || !credentials.username || !credentials.password) {
            throw new Error("Usuario y contraseña son requeridos");
          }

          // Sanitizar username para prevenir inyección
          const username = credentials.username.trim().slice(0, 50);
          const password = credentials.password;

          if (username.length < 3 || username.length > 20) {
            throw new Error("Usuario o contraseña incorrectos");
          }

          const { db } = await connectToDatabase();
          
          // Usar query sanitizado para prevenir inyección NoSQL
          const user = await db.collection("users").findOne({
            username: username,
          });

          if (!user) {
            // No revelar si el usuario existe o no (mejor seguridad)
            throw new Error("Usuario o contraseña incorrectos");
          }

          const isValid = await bcrypt.compare(
            password,
            user.password
          );

          if (!isValid) {
            throw new Error("Usuario o contraseña incorrectos");
          }

          return {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            username: user.username,
            image: user.image || null,
          };
        } catch (error) {
          console.error("Error en autorización:", error);
          return null;
        }
      },
    }),
  ],

  callbacks: {
    async session(session, token) {
      if (token) {
        session.user.id = token.id;
        session.user.username = token.username;
        session.user.name = token.name;
        session.user.email = token.email;
        session.user.image = token.image;
      }

      // Obtener la imagen actualizada del usuario desde la base de datos
      const { db } = await connectToDatabase();
      const user = await db.collection("users").findOne({ email: session.user.email });
      if (user && user.image) {
        session.user.image = user.image;
      }

      session.admin = false;
      const result = await db
        .collection("admins")
        .findOne({ user: session.user.email });
      if (result) {
        session.admin = true;
      }
      return session;
    },
    async jwt(token, user, account) {
      if (user) {
        token.id = user.id;
        token.username = user.username;
        token.name = user.name;
        token.email = user.email;
        token.image = user.image;
      }
      return token;
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 días
  },
  cookies: {
    sessionToken: {
      name: `next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
      },
    },
  },
  secret: process.env.NEXTAUTH_SECRET || (process.env.NODE_ENV === 'production' ? undefined : 'development-secret-key-change-in-production'),
  theme: "dark",
});
