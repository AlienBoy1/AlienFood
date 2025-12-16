// API route para servir el manifest sin autenticación
import fs from 'fs';
import path from 'path';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  try {
    const manifestPath = path.join(process.cwd(), 'public', 'img', 'favicons', 'site.webmanifest');
    const manifestContent = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestContent);

    res.setHeader('Content-Type', 'application/manifest+json');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.status(200).json(manifest);
  } catch (error) {
    console.error('Error reading manifest:', error);
    // Fallback: devolver un manifest básico
    return res.status(200).json({
      name: "TUNEL DEL TIEMPO",
      short_name: "Túnel",
      icons: [
        {
          src: "/img/favicons/android-chrome-192x192.png",
          sizes: "192x192",
          type: "image/png"
        },
        {
          src: "/img/favicons/android-chrome-512x512.png",
          sizes: "512x512",
          type: "image/png"
        }
      ],
      start_url: "/",
      display: "standalone",
      theme_color: "#6366f1",
      background_color: "#1e1b4b"
    });
  }
}

