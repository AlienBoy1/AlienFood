// Script para poblar la base de datos con productos reales de TUNEL DEL TIEMPO
const { MongoClient } = require('mongodb');
const path = require('path');
const fs = require('fs');

// Cargar variables de entorno
const envLocalPath = path.join(process.cwd(), '.env.local');
if (fs.existsSync(envLocalPath)) {
  require('dotenv').config({ path: envLocalPath });
} else {
  require('dotenv').config();
}

const products = [
  // Figuras Marvel
  {
    title: "Figura de Acción Spider-Man Marvel Legends",
    price: 899,
    description: "Figura articulada de 15cm con múltiples accesorios. Incluye base y efectos web. Edición coleccionable.",
    category: "Figuras Marvel",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Iron Man Mark 50 Hot Toys",
    price: 4599,
    description: "Figura premium de 30cm con iluminación LED, múltiples accesorios y base con nombre. Edición limitada.",
    category: "Figuras Marvel",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  {
    title: "Thor Ragnarok Marvel Select",
    price: 1299,
    description: "Figura de 20cm con martillo Mjolnir y efectos de rayo. Altamente detallada y articulada.",
    category: "Figuras Marvel",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Figuras DC
  {
    title: "Batman Arkham Knight McFarlane Toys",
    price: 799,
    description: "Figura de acción de 17cm basada en el videojuego. Incluye múltiples accesorios y base.",
    category: "Figuras DC",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Superman DC Multiverse",
    price: 899,
    description: "Figura clásica de Superman con capa y múltiples poses. Edición coleccionable de 18cm.",
    category: "Figuras DC",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  {
    title: "Wonder Woman 1984 Premium",
    price: 1599,
    description: "Figura premium de 25cm con escudo, espada y lazo de la verdad. Detalles excepcionales.",
    category: "Figuras DC",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Dragon Ball Super
  {
    title: "Goku Ultra Instinct Bandai",
    price: 1299,
    description: "Figura SH Figuarts de Goku en Ultra Instinct. Altamente articulada con efectos de energía.",
    category: "Dragon Ball Super",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Vegeta Super Saiyan Blue",
    price: 1199,
    description: "Figura articulada de Vegeta con efectos de aura azul. Incluye múltiples caras intercambiables.",
    category: "Dragon Ball Super",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  {
    title: "Gohan Beast Banpresto",
    price: 899,
    description: "Figura de Gohan en forma Beast. Escala 1/10 con base especial y efectos de poder.",
    category: "Dragon Ball Super",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Carritos Batman
  {
    title: "Batmobile 1989 Hot Wheels Premium",
    price: 599,
    description: "Réplica detallada del Batmobile de la película de 1989. Escala 1:18 con apertura de puertas.",
    category: "Carritos Batman",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Batmobile The Dark Knight",
    price: 799,
    description: "Modelo del Batmobile de la trilogía de Nolan. Incluye detalles interiores y efectos de luces.",
    category: "Carritos Batman",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Mini Consolas Retro
  {
    title: "Nintendo Classic Mini NES",
    price: 2499,
    description: "Consola retro con 30 juegos preinstalados. Incluye 2 controles y HDMI. Edición limitada.",
    category: "Mini Consolas Retro",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Sega Genesis Mini",
    price: 2199,
    description: "Consola retro con 42 juegos clásicos. Incluye 2 controles de 6 botones y cable HDMI.",
    category: "Mini Consolas Retro",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  {
    title: "PlayStation Classic",
    price: 1999,
    description: "Mini consola con 20 juegos preinstalados. Incluye 2 controles y cable HDMI.",
    category: "Mini Consolas Retro",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Discos Música 80s
  {
    title: "Michael Jackson - Thriller (Vinilo)",
    price: 899,
    description: "Álbum clásico de 1982 en vinilo de 180g. Edición remasterizada con portada original.",
    category: "Discos Música 80s",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Madonna - Like a Virgin (CD)",
    price: 399,
    description: "CD original de 1984. Incluye todos los éxitos del álbum. Estado excelente.",
    category: "Discos Música 80s",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Discos Música 90s
  {
    title: "Nirvana - Nevermind (Vinilo)",
    price: 1299,
    description: "Vinilo de 180g del álbum icónico de 1991. Edición especial con portada original.",
    category: "Discos Música 90s",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Backstreet Boys - Millennium (CD)",
    price: 299,
    description: "CD original de 1999. Incluye todos los éxitos del álbum. Estado como nuevo.",
    category: "Discos Música 90s",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Discos Música 2000s
  {
    title: "Eminem - The Marshall Mathers LP (CD)",
    price: 449,
    description: "CD original de 2000. Edición especial con bonus tracks. Estado excelente.",
    category: "Discos Música 2000s",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Discos Video 80s
  {
    title: "Back to the Future - VHS Original",
    price: 599,
    description: "VHS original de 1985. Película completa en su formato original. Coleccionable.",
    category: "Discos Video 80s",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "The Goonies - DVD Edición Especial",
    price: 399,
    description: "DVD de la película de 1985. Incluye contenido extra y comentarios del director.",
    category: "Discos Video 80s",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Discos Video 90s
  {
    title: "Titanic - DVD Coleccionista",
    price: 499,
    description: "DVD de la edición especial con múltiples discos. Incluye documentales y escenas eliminadas.",
    category: "Discos Video 90s",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Discos Video 2000s
  {
    title: "The Lord of the Rings - Trilogía Blu-ray",
    price: 1299,
    description: "Trilogía completa en Blu-ray con edición extendida. Incluye todos los extras.",
    category: "Discos Video 2000s",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  
  // Figuras de Acción
  {
    title: "G.I. Joe Snake Eyes Classified",
    price: 699,
    description: "Figura de acción de 15cm con múltiples accesorios. Altamente articulada y detallada.",
    category: "Figuras de Acción",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Juguetes Retro
  {
    title: "Transformers Optimus Prime G1",
    price: 2499,
    description: "Réplica del Optimus Prime original de los 80s. Se transforma de camión a robot. Edición coleccionable.",
    category: "Juguetes Retro",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "He-Man Masters of the Universe",
    price: 899,
    description: "Figura clásica de He-Man de los 80s. Incluye espada del poder y accesorios originales.",
    category: "Juguetes Retro",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Coleccionables
  {
    title: "Funko Pop! Batman 80th Anniversary",
    price: 599,
    description: "Funko Pop exclusivo del 80 aniversario de Batman. Edición limitada con certificado.",
    category: "Coleccionables",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "Hot Toys Iron Man Mark 85",
    price: 5999,
    description: "Figura premium de 30cm con iluminación LED y múltiples accesorios. Edición limitada.",
    category: "Coleccionables",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Superhéroes
  {
    title: "Marvel Legends Wolverine",
    price: 999,
    description: "Figura articulada de Wolverine con garras retráctiles. Incluye múltiples accesorios.",
    category: "Superhéroes",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  
  // Anime
  {
    title: "Naruto Shippuden Figuarts",
    price: 1199,
    description: "Figura SH Figuarts de Naruto modo sabio. Altamente articulada con efectos especiales.",
    category: "Anime",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  {
    title: "One Piece Luffy Gear 5",
    price: 1399,
    description: "Figura de Luffy en Gear 5. Incluye efectos de poder y múltiples poses.",
    category: "Anime",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  
  // Videojuegos Retro
  {
    title: "Super Mario Bros. 3 NES",
    price: 799,
    description: "Cartucho original de NES de Super Mario Bros. 3. Funcional y en buen estado.",
    category: "Videojuegos Retro",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  },
  {
    title: "Sonic the Hedgehog Genesis",
    price: 599,
    description: "Cartucho original de Sega Genesis. Juego completo y funcional. Estado excelente.",
    category: "Videojuegos Retro",
    image: "https://images.unsplash.com/photo-1608889476561-6242cfdbf622?w=500"
  },
  
  // Accesorios
  {
    title: "Base para Figuras Premium",
    price: 199,
    description: "Base de exhibición con iluminación LED para figuras de hasta 30cm. Incluye cable USB.",
    category: "Accesorios",
    image: "https://images.unsplash.com/photo-1534809027769-b00d750a6bac?w=500"
  },
  {
    title: "Estuche Protector para Vinilos",
    price: 149,
    description: "Estuche protector de vinilo con funda interior. Protege tus discos de colección.",
    category: "Accesorios",
    image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=500"
  }
];

async function populateProducts() {
  const uri = process.env.MONGODB_URI;
  
  if (!uri) {
    console.error('❌ MONGODB_URI no está definida');
    process.exit(1);
  }

  const client = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    console.log('✅ Conectado a MongoDB\n');

    // Usar la base de datos 'zinger' en lugar de la predeterminada
    const dbName = process.env.MONGODB_DB || 'zinger';
    const db = client.db(dbName);
    console.log(`📁 Usando base de datos: ${dbName}\n`);
    const dishesCollection = db.collection('dishes');

    // Eliminar todos los productos de comida existentes
    console.log('🗑️  Eliminando productos antiguos...');
    const deleteResult = await dishesCollection.deleteMany({});
    console.log(`   ✅ ${deleteResult.deletedCount} productos eliminados\n`);

    // Insertar los nuevos productos
    console.log('📝 Insertando nuevos productos...');
    const result = await dishesCollection.insertMany(products);
    console.log(`\n✅ ${result.insertedCount} productos insertados exitosamente:\n`);

    // Mostrar productos por categoría
    const categories = [...new Set(products.map(p => p.category))];
    categories.forEach(category => {
      const categoryProducts = products.filter(p => p.category === category);
      console.log(`\n📦 ${category} (${categoryProducts.length} productos):`);
      categoryProducts.forEach((product, index) => {
        console.log(`   ${index + 1}. ${product.title} - $${product.price} MXN`);
      });
    });

    console.log('\n🎉 ¡Base de datos poblada correctamente!');

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    process.exit(1);
  } finally {
    await client.close();
    console.log('\n✅ Conexión cerrada');
  }
}

populateProducts();

