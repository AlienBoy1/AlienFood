import Image from "next/image";
import Fade from "react-reveal/Fade";
import { useState } from "react";

function Testimonials() {
  const [hoveredIndex, setHoveredIndex] = useState(null);

  const testimonials = [
    {
      text: "¡TUNEL DEL TIEMPO es increíble! Encontré figuras de acción que pensé que nunca volvería a ver. La calidad es excelente y el servicio al cliente es excepcional. ¡Mi colección nunca había estado tan completa!",
      author: "Carlos Mendoza",
      image: "/img/testimonials/customer-1.jpg",
      rating: 5,
    },
    {
      text: "Productos auténticos de los 80s y 90s, exactamente como los recordaba. Las mini consolas retro que compré funcionan perfectamente. ¡Es como viajar en el tiempo! Definitivamente volveré por más.",
      author: "Ana García",
      image: "/img/testimonials/customer-2.jpg",
      rating: 5,
    },
    {
      text: "La mejor tienda de coleccionables que he encontrado. Los discos de música que compré están en perfecto estado y los precios son justos. El envío fue rápido y el empaque cuidadoso. ¡Altamente recomendado!",
      author: "Roberto Sánchez",
      image: "/img/testimonials/customer-3.jpg",
      rating: 5,
    },
  ];

  return (
    <div className="px-6 py-20 bg-gray-50 dark:bg-gray-900">
      <div className="mx-auto max-w-screen-xl">
        <Fade bottom>
          <h2 className="heading mb-4">Lo Que Dicen Nuestros Clientes</h2>
          <p className="text-center text-gray-600 dark:text-gray-400 max-w-2xl mx-auto mb-16">
            Miles de coleccionistas confían en nosotros para encontrar sus tesoros favoritos
          </p>
        </Fade>
        <div className="flex justify-between mt-20 gap-6 sm:flex-row flex-col">
          {testimonials.map((testimonial, index) => {
            const isHovered = hoveredIndex === index;
            
            return (
              <Fade key={`testimonial-${index}`} bottom delay={index * 150}>
                <div
                  className="sm:max-w-xs flex-1 bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg hover:shadow-2xl transform transition-all duration-300 cursor-pointer group"
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  style={{
                    transform: isHovered ? "translateY(-8px)" : "translateY(0)",
                  }}
                >
                  <div className="font-extrabold text-6xl text-primary-light opacity-20 -mb-4 -mt-2">
                    "
                  </div>
                  <div className="flex mb-4">
                    {[...Array(testimonial.rating)].map((_, i) => (
                      <svg
                        key={i}
                        className="w-5 h-5 text-yellow-400"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                      </svg>
                    ))}
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-6 italic">
                    {testimonial.text}
                  </p>
                  <div className="flex items-center gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                    <div className="relative">
                      <Image
                        src={testimonial.image}
                        alt={testimonial.author}
                        width={50}
                        height={50}
                        objectFit="cover"
                        className="rounded-full ring-2 ring-primary-light"
                      />
                    </div>
                    <div>
                      <span className="font-semibold text-gray-800 dark:text-gray-200 block">
                        {testimonial.author}
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        Cliente Verificado
                      </span>
                    </div>
                  </div>
                </div>
              </Fade>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default Testimonials;
