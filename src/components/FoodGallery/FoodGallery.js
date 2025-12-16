import Fade from "react-reveal/Fade";
import { useState, useEffect } from "react";
import useSWR from "swr";
import fetcher from "../../util/fetch";

function FoodGallery() {
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const { data: dishes } = useSWR("/api/dishes", fetcher);
  
  // Obtener imágenes de productos reales de diferentes categorías
  const getGalleryImages = () => {
    if (!dishes || !Array.isArray(dishes) || dishes.length === 0) {
      // Imágenes placeholder si no hay productos
      return [
        { src: "/img/tunel-logo.svg", title: "TUNEL DEL TIEMPO" },
        { src: "/img/tunel-logo.svg", title: "Coleccionables" },
        { src: "/img/tunel-logo.svg", title: "Figuras de Acción" },
        { src: "/img/tunel-logo.svg", title: "Consolas Retro" },
        { src: "/img/tunel-logo.svg", title: "Discos Retro" },
        { src: "/img/tunel-logo.svg", title: "Superhéroes" },
        { src: "/img/tunel-logo.svg", title: "Anime" },
        { src: "/img/tunel-logo.svg", title: "Juguetes" },
      ];
    }
    
    // Agrupar productos por categoría y tomar uno de cada categoría
    const categoriesMap = new Map();
    dishes.forEach(dish => {
      if (dish.image && dish.category && !categoriesMap.has(dish.category)) {
        categoriesMap.set(dish.category, {
          src: dish.image,
          title: dish.category
        });
      }
    });
    
    // Si tenemos suficientes categorías, usar esas imágenes
    if (categoriesMap.size >= 4) {
      const categoryImages = Array.from(categoriesMap.values());
      // Rellenar hasta 8 si es necesario
      while (categoryImages.length < 8 && dishes.length > categoryImages.length) {
        const remainingDishes = dishes.filter(d => d.image && !categoryImages.some(ci => ci.src === d.image));
        if (remainingDishes.length > 0) {
          const dish = remainingDishes[0];
          categoryImages.push({
            src: dish.image,
            title: dish.category || dish.title
          });
        } else {
          break;
        }
      }
      return categoryImages.slice(0, 8);
    }
    
    // Si no, usar las primeras 8 imágenes de productos disponibles
    const productImages = dishes
      .filter(d => d.image)
      .slice(0, 8)
      .map(d => ({
        src: d.image,
        title: d.category || d.title
      }));
    
    // Rellenar con logo si es necesario
    while (productImages.length < 8) {
      productImages.push({
        src: "/img/tunel-logo.svg",
        title: `Producto ${productImages.length + 1}`
      });
    }
    
    return productImages.slice(0, 8);
  };
  
  const galleryImages = getGalleryImages();

  return (
    <div className="w-full py-12 sm:py-20 bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6">
        <Fade bottom>
          <h2 className="heading mb-12">Galería de Coleccionables</h2>
        </Fade>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
          {galleryImages.map((item, i) => (
            <Fade key={`gallery-${i}`} bottom delay={i * 100}>
              <div
                className="relative w-full overflow-hidden bg-black rounded-lg group cursor-pointer transform transition-all duration-300 hover:scale-105 hover:shadow-2xl"
                onMouseEnter={() => setHoveredIndex(i)}
                onMouseLeave={() => setHoveredIndex(null)}
              >
                <div className="aspect-square relative">
                  <img
                    src={item.src}
                    alt={item.title}
                    className={`w-full h-full object-cover transition-all duration-500 ${
                      hoveredIndex === i ? "scale-110 opacity-90" : "opacity-70"
                    }`}
                    onError={(e) => {
                      // Fallback al logo si la imagen falla
                      e.target.src = "/img/tunel-logo.svg";
                    }}
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                  <div className="absolute bottom-0 left-0 right-0 p-3 transform translate-y-full group-hover:translate-y-0 transition-transform duration-300">
                    <p className="text-white text-sm font-medium">{item.title}</p>
                  </div>
                </div>
              </div>
            </Fade>
          ))}
        </div>
      </div>
    </div>
  );
}

export default FoodGallery;
