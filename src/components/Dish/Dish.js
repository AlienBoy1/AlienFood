import Image from "next/image";
import Currency from "react-currency-formatter";
import { useDispatch } from "react-redux";
import { addToCart } from "../../slices/cartSlice";
import Fade from "react-reveal/Fade";
import { ShoppingCartIcon, HeartIcon } from "@heroicons/react/solid";
import { useState } from "react";

function Dish({ _id, title, price, description, category, image }) {
  const dispatch = useDispatch();
  const [isHovered, setIsHovered] = useState(false);
  const [isLiked, setIsLiked] = useState(false);

  const addItemToCart = () => {
    dispatch(
      addToCart({
        _id,
        title,
        price,
        description,
        category,
        image,
        qty: 1,
        toast: true,
      })
    );
  };

  return (
    <Fade bottom>
      <div
        className="relative flex flex-col bg-white dark:bg-gray-800 z-20 md:p-6 p-4 rounded-xl shadow-lg hover:shadow-2xl transform transition-all duration-300 group"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        style={{
          transform: isHovered ? "translateY(-8px)" : "translateY(0)",
        }}
      >
        {/* Badge de categoría */}
        <div className="absolute top-3 right-3 z-10">
          <span className="px-3 py-1 text-xs font-medium rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 text-white capitalize shadow-lg">
            {category}
          </span>
        </div>

        {/* Botón de favorito */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            setIsLiked(!isLiked);
          }}
          className="absolute top-3 left-3 z-10 p-2 rounded-full bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm shadow-lg hover:scale-110 transition-transform duration-200"
        >
          <HeartIcon
            className={`w-5 h-5 transition-colors duration-200 ${
              isLiked ? "text-red-500 fill-current" : "text-gray-400"
            }`}
          />
        </button>

        {/* Imagen del producto */}
        <div className="relative w-full h-48 mb-4 rounded-lg overflow-hidden bg-gray-100 dark:bg-gray-700">
          <Image
            src={image}
            height={200}
            width={200}
            alt={title}
            objectFit="cover"
            objectPosition="center"
            unoptimized={image?.startsWith('http')}
            className={`transition-transform duration-500 ${
              isHovered ? "scale-110" : "scale-100"
            }`}
          />
          <div className="absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        </div>

        {/* Información del producto */}
        <h4 className="my-2 font-semibold text-lg capitalize text-gray-800 dark:text-gray-200 line-clamp-1">
          {title}
        </h4>
        <p className="text-xs mb-3 line-clamp-2 text-gray-600 dark:text-gray-400 min-h-[2.5rem]">
          {description}
        </p>
        
        {/* Precio */}
        <div className="mb-4 mt-auto">
          <div className="flex items-baseline gap-2">
            <span className="font-bold text-2xl text-gray-800 dark:text-gray-200">
              <Currency quantity={price} currency="MXN" />
            </span>
          </div>
        </div>

        {/* Botón de agregar al carrito */}
        <button
          className={`mt-auto button flex items-center justify-center gap-2 transition-all duration-300 ${
            isHovered
              ? "bg-gradient-to-r from-indigo-600 to-purple-600 shadow-lg"
              : ""
          }`}
          onClick={addItemToCart}
        >
          <ShoppingCartIcon className="w-5 h-5" />
          <span>Agregar al Carrito</span>
        </button>
      </div>
    </Fade>
  );
}

export default Dish;
