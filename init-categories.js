// Script para inicializar las categorías de TUNEL DEL TIEMPO
const { MongoClient } = require('mongodb');
const path = require('path');
const fs = require('fs');

// Intentar cargar dotenv desde diferentes ubicaciones
let envLoaded = false;

// Primero intentar con .env.local (Next.js usa este por defecto)
const envLocalPath = path.join(process.cwd(), '.env.local');
if (fs.existsSync(envLocalPath)) {
  require('dotenv').config({ path: envLocalPath });
  console.log('📄 Cargando variables desde .env.local');
  envLoaded = true;
} else {
  // Si no existe .env.local, intentar con .env
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    require('dotenv').config({ path: envPath });
    console.log('📄 Cargando variables desde .env');
    envLoaded = true;
  } else {
    // Último intento: cargar sin especificar ruta
    try {
      require('dotenv').config();
      envLoaded = true;
    } catch (error) {
      console.warn('⚠️  No se encontró archivo .env o .env.local');
    }
  }
}

// También verificar si la variable viene como argumento de línea de comandos
const args = process.argv.slice(2);
let mongoUriFromArgs = null;
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith('MONGODB_URI=')) {
    mongoUriFromArgs = args[i].split('=')[1];
    break;
  }
}

const categories = [
  { name: "Figuras Marvel" },
  { name: "Figuras DC" },
  { name: "Dragon Ball Super" },
  { name: "Carritos Batman" },
  { name: "Mini Consolas Retro" },
  { name: "Discos Música 80s" },
  { name: "Discos Música 90s" },
  { name: "Discos Música 2000s" },
  { name: "Discos Video 80s" },
  { name: "Discos Video 90s" },
  { name: "Discos Video 2000s" },
  { name: "Figuras de Acción" },
  { name: "Juguetes Retro" },
  { name: "Coleccionables" },
  { name: "Superhéroes" },
  { name: "Anime" },
  { name: "Videojuegos Retro" },
  { name: "Accesorios" }
];

async function initCategories() {
  // Intentar obtener la URI de diferentes formas
  const uri = mongoUriFromArgs || process.env.MONGODB_URI || process.env.NEXT_PUBLIC_MONGODB_URI;
  
  if (!uri) {
    console.error('\n❌ MONGODB_URI no está definida en las variables de entorno\n');
    console.log('💡 Soluciones:\n');
    console.log('   1. Crea un archivo .env.local en la raíz del proyecto con:');
    console.log('      MONGODB_URI=tu_uri_aqui\n');
    console.log('   2. O ejecuta el script pasando la URI como argumento:');
    console.log('      node init-categories.js MONGODB_URI=tu_uri_aqui\n');
    console.log('   3. O exporta la variable antes de ejecutar (Linux/Mac):');
    console.log('      export MONGODB_URI=tu_uri_aqui');
    console.log('      node init-categories.js\n');
    console.log('   4. O en PowerShell (Windows):');
    console.log('      $env:MONGODB_URI="tu_uri_aqui"');
    console.log('      node init-categories.js\n');
    
    if (!envLoaded) {
      console.log('📋 Archivos .env encontrados:');
      const envFiles = ['.env.local', '.env'].filter(file => 
        fs.existsSync(path.join(process.cwd(), file))
      );
      if (envFiles.length > 0) {
        console.log('   ✅', envFiles.join(', '));
      } else {
        console.log('   ❌ No se encontraron archivos .env o .env.local');
        console.log('   💡 Puedes copiar .env.example a .env.local y completarlo');
      }
    }
    
    process.exit(1);
  }

  console.log('🔗 URI de MongoDB detectada');
  console.log('   Primeros caracteres:', uri.substring(0, 30) + '...\n');

  const client = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    console.log('🔄 Conectando a MongoDB...');
    await client.connect();
    console.log('✅ Conectado a MongoDB\n');

    // Usar la base de datos 'zinger' en lugar de la predeterminada
    const dbName = process.env.MONGODB_DB || 'zinger';
    const db = client.db(dbName);
    console.log(`📁 Usando base de datos: ${dbName}`);
    const categoriesCollection = db.collection('categories');

    // Verificar si ya existen categorías
    const existingCategories = await categoriesCollection.find({}).toArray();
    
    if (existingCategories.length > 0) {
      console.log(`⚠️  Ya existen ${existingCategories.length} categorías en la base de datos:\n`);
      existingCategories.forEach((cat, index) => {
        console.log(`   ${index + 1}. ${cat.name}`);
      });
      console.log('\n💡 Si deseas agregar las nuevas categorías:');
      console.log('   1. Elimina las existentes desde MongoDB Atlas o Compass');
      console.log('   2. O modifica este script para agregar solo las que faltan');
      console.log('   3. O ejecuta este script nuevamente después de limpiar la colección\n');
      return;
    }

    // Insertar las nuevas categorías
    console.log('📝 Insertando categorías...');
    const result = await categoriesCollection.insertMany(categories);
    console.log(`\n✅ ${result.insertedCount} categorías insertadas exitosamente:\n`);
    
    categories.forEach((cat, index) => {
      console.log(`   ${index + 1}. ${cat.name}`);
    });

    console.log('\n🎉 ¡Categorías inicializadas correctamente!');

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    if (error.message.includes('authentication')) {
      console.error('\n💡 Verifica que las credenciales de MongoDB sean correctas');
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
      console.error('\n💡 Verifica que la URI de MongoDB sea correcta y que tengas conexión a internet');
    } else if (error.message.includes('timeout')) {
      console.error('\n💡 Verifica tu conexión a internet y que la URI de MongoDB sea accesible');
    }
    process.exit(1);
  } finally {
    await client.close();
    console.log('\n✅ Conexión cerrada');
  }
}

initCategories();
