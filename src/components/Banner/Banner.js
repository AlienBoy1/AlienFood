import Image from "next/image";
import Fade from "react-reveal/Fade";
import { SparklesIcon, ArrowDownIcon } from "@heroicons/react/solid";
import { useState, useEffect } from "react";

function Banner() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  useEffect(() => {
    const handleMouseMove = (e) => {
      setMousePosition({
        x: (e.clientX / window.innerWidth - 0.5) * 20,
        y: (e.clientY / window.innerHeight - 0.5) * 20,
      });
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  const orderNow = () => {
    window.scrollTo({
      top: document.getElementById("menu").offsetTop - 90,
      behavior: "smooth",
    });
  };

  const viewMore = () => {
    window.scrollTo({
      top: document.getElementById("about").offsetTop - 90,
      behavior: "smooth",
    });
  };

  return (
    <div className="px-3 sm:px-6 relative heightFix mb-12 sm:mb-24 overflow-hidden bg-gradient-to-br from-indigo-50 via-purple-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      {/* Elementos decorativos animados */}
      <div className="absolute lg:-bottom-60 -bottom-72 lg:-left-44 -left-80 object-contain overflow-hidden opacity-20">
        <Fade left>
          <div
            className="w-96 h-96 rounded-full bg-gradient-to-br from-indigo-400 to-purple-400 blur-3xl"
            style={{
              transform: `translate(${mousePosition.x * 0.5}px, ${mousePosition.y * 0.5}px)`,
            }}
          />
        </Fade>
      </div>

      <div className="absolute top-16 lg:left-72 left-60 lg:w-auto sm:w-10 w-8 object-contain overflow-hidden opacity-30">
        <Fade top>
          <div
            className="w-20 h-20 rounded-full bg-gradient-to-br from-pink-400 to-rose-400 blur-2xl"
            style={{
              transform: `translate(${mousePosition.x * 0.3}px, ${mousePosition.y * 0.3}px)`,
            }}
          />
        </Fade>
      </div>

      {/* Partículas flotantes */}
      {[...Array(6)].map((_, i) => (
        <div
          key={`particle-${i}`}
          className="absolute w-2 h-2 rounded-full bg-gradient-to-r from-indigo-400 to-purple-400 opacity-60 animate-pulse"
          style={{
            left: `${20 + i * 15}%`,
            top: `${30 + (i % 2) * 40}%`,
            animationDelay: `${i * 0.5}s`,
            animationDuration: `${3 + i * 0.5}s`,
          }}
        />
      ))}

      <div className="max-w-screen-xl mx-auto lg:py-10 sm:pt-32 pt-20 relative z-10">
        <div className="flex lg:justify-between lg:items-center overflow-hidden p-0.5 lg:flex-row flex-col lg:gap-4 gap-8">
          <Fade left>
            <div className="main_heading">
              <div className="flex items-center gap-2 mb-4">
                <SparklesIcon className="w-6 h-6 text-primary-light animate-pulse" />
                <h3 className="font-medium sm:text-xl text-base text-gray-600 dark:text-gray-400">
                  Viaja en el Tiempo
                </h3>
              </div>
              <h1 className="font-bold xl:text-7xl sm:text-6xl xxs:text-5xl text-4xl mb-4">
                TUNEL DEL{" "}
                <span className="bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 bg-clip-text text-transparent animate-gradient">
                  TIEMPO
                </span>
              </h1>
              <p className="text-gray-700 dark:text-gray-300 mt-4 text-sm sm:text-base max-w-md leading-relaxed">
                Descubre figuras de acción, juguetes retro, consolas clásicas y
                coleccionables de los 80s, 90s y 2000s. Revive tus mejores
                recuerdos.
              </p>
              <div className="flex items-center xl:mt-12 lg:mt-10 sm:mt-8 mt-6 gap-3 sm:gap-4 flex-wrap">
                <button
                  className="button text-sm sm:text-base xl:px-16 px-8 sm:px-14 py-3 sm:py-3.5 transition-all duration-300 hover:scale-105 hover:shadow-xl flex items-center gap-2"
                  onClick={orderNow}
                >
                  <SparklesIcon className="w-5 h-5" />
                  <span>Explorar Productos</span>
                </button>
                <button
                  className="xl:px-16 lg:text-base text-sm sm:text-base button-ghost px-8 sm:px-14 py-3 sm:py-3.5 transition-all duration-300 hover:scale-105 flex items-center gap-2"
                  onClick={viewMore}
                >
                  <ArrowDownIcon className="w-5 h-5" />
                  <span>Ver Más</span>
                </button>
              </div>
            </div>
          </Fade>
          <Fade right>
            <div
              className="lg:w-1/2 lg:m-0 lg:max-w-none sm:max-w-lg max-w-xs mx-auto relative"
              style={{
                transform: `translate(${mousePosition.x * 0.1}px, ${mousePosition.y * 0.1}px) rotate(${mousePosition.x * 0.05}deg)`,
                transition: "transform 0.3s ease-out",
              }}
            >
              <div className="absolute inset-0 bg-gradient-to-r from-indigo-400/20 to-purple-400/20 rounded-full blur-3xl animate-pulse" />
              <Image
                src="/img/tunel-logo.svg"
                alt="TUNEL DEL TIEMPO"
                width={600}
                height={600}
                objectFit="contain"
                className="relative z-10 drop-shadow-2xl"
              />
            </div>
          </Fade>
        </div>
      </div>
    </div>
  );
}

export default Banner;
