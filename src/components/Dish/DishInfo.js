import { useState } from "react";
import Currency from "react-currency-formatter";
import Image from "next/image";
import { useRouter } from "next/router";
import axios from "axios";
import NormalToast from "../../util/Toast/NormalToast";
import Fade from "react-reveal/Fade";

function DishInfo({
  _id,
  title,
  price,
  description,
  category,
  image,
  border,
  removeFromSearchResults,
}) {
  const router = useRouter();
  const [disabled, setDisabled] = useState(false);
  const [isHovered, setIsHovered] = useState(false);

  const deleteDish = (_id) => {
    if (!confirm("¿Estás seguro de que deseas eliminar este producto?")) {
      return;
    }
    
    setDisabled(true);
    axios
      .post("/api/admin/delete-dish", { _id })
      .then(() => {
        NormalToast("Producto eliminado exitosamente");
        removeFromSearchResults(_id);
        setDisabled(false);
      })
      .catch((err) => {
        NormalToast("Algo salió mal", true);
        console.error(err);
        setDisabled(false);
      });
  };

  return (
    <Fade bottom>
      <div
        className={`flex sm:flex-row flex-col-reverse w-full my-4 text-sm text-gray-700 dark:text-gray-300 py-6 px-4 rounded-lg transition-all duration-300 ${
          border ? "border-b border-gray-200 dark:border-gray-700" : ""
        } sm:justify-between gap-6 hover:bg-gray-50 dark:hover:bg-gray-800/50`}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        <div className="space-y-3 flex-1">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="font-semibold text-lg capitalize text-gray-800 dark:text-gray-200">
                {title}
              </div>
              <div className="inline-block mt-1 px-2 py-1 text-xs font-medium rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 text-white capitalize">
                {category}
              </div>
            </div>
          </div>
          <p className="text-gray-600 dark:text-gray-400 lg:text-sm text-xs leading-relaxed">
            {description}
          </p>
          <div>
            <p className="font-semibold text-lg">
              <span className="font-normal text-gray-600 dark:text-gray-400">Precio - </span>
              <Currency quantity={price} currency="MXN" />
            </p>
          </div>
          <div className="flex items-center gap-4 pt-2">
            <button
              className={`button py-2 px-6 text-sm transition-all duration-300 ${
                disabled ? "opacity-50 cursor-not-allowed" : "hover:scale-105"
              }`}
              onClick={() => router.push(`/admin/update-dish/${_id}`)}
              disabled={disabled}
            >
              Actualizar
            </button>
            <button
              className={`button-red py-2 px-6 text-sm transition-all duration-300 ${
                disabled ? "opacity-50 cursor-not-allowed" : "hover:scale-105"
              }`}
              onClick={() => deleteDish(_id)}
              disabled={disabled}
            >
              Eliminar
            </button>
          </div>
        </div>
        <div className="sm:mx-0 sm:ml-6 min-w-max mx-auto my-auto">
          <div className="relative w-32 h-32 rounded-lg overflow-hidden shadow-lg group">
            <Image
              src={image}
              width={120}
              height={120}
              alt={title}
              objectFit="cover"
              unoptimized={image?.startsWith('http')}
              className={`transition-transform duration-300 ${
                isHovered ? "scale-110" : "scale-100"
              }`}
            />
          </div>
        </div>
      </div>
    </Fade>
  );
}

export default DishInfo;
