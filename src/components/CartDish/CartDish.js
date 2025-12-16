import { MinusSmIcon, PlusIcon, TrashIcon } from "@heroicons/react/solid";
import Image from "next/image";
import Currency from "react-currency-formatter";
import { useDispatch } from "react-redux";
import { updateQty, removeFromCart } from "../../slices/cartSlice";
import Fade from "react-reveal/Fade";
import { useState } from "react";

function CartDish({
  _id,
  title,
  price,
  description,
  category,
  image,
  qty,
  border,
  disabled,
}) {
  const dispatch = useDispatch();
  const total = price * qty;
  const [isHovered, setIsHovered] = useState(false);

  const removeItemFromCart = () => dispatch(removeFromCart({ _id }));
  const incQty = () =>
    dispatch(
      updateQty({
        _id,
        title,
        price,
        description,
        category,
        image,
        qty: qty + 1,
      })
    );
  const decQty = () =>
    dispatch(
      updateQty({
        _id,
        title,
        price,
        description,
        category,
        image,
        qty: qty - 1,
      })
    );

  return (
    <Fade bottom>
      <div
        className={`block bg-gradient-to-r from-white to-gray-50 dark:from-gray-800 dark:to-gray-700 py-6 sm:grid sm:grid-cols-5 gap-4 rounded-lg px-4 transition-all duration-300 hover:shadow-lg ${
          border ? "border-b border-gray-200 dark:border-gray-600 mb-4" : ""
        }`}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        style={{
          transform: isHovered ? "translateX(4px)" : "translateX(0)",
        }}
      >
        {/* Imagen */}
        <div className="text-center sm:text-left my-auto mx-auto sm:mx-0">
          <div className="relative w-24 h-24 rounded-lg overflow-hidden shadow-md group">
            <Image
              src={image}
              width={100}
              height={100}
              objectFit="cover"
              alt={title}
              objectPosition="center"
              unoptimized={image?.startsWith('http')}
              className={`transition-transform duration-300 ${
                isHovered ? "scale-110" : "scale-100"
              }`}
            />
          </div>
        </div>

        {/* Información del producto */}
        <div className="col-span-3 sm:p-4 mt-4 mb-6 sm:my-0">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <h4 className="mb-2 lg:text-xl md:text-lg text-base capitalize font-semibold text-gray-800 dark:text-gray-200">
                {title}
              </h4>
              <span className="inline-block px-2 py-1 text-xs font-medium rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 text-white mb-2">
                {category}
              </span>
              <p className="lg:text-sm text-xs my-2 mb-4 line-clamp-2 text-gray-600 dark:text-gray-400">
                {description}
              </p>
              <div className="flex items-baseline gap-2">
                <span className="font-medium md:text-base text-sm text-gray-700 dark:text-gray-300">
                  {qty} × <Currency quantity={price} currency="MXN" /> =
                </span>
                <span className="font-bold text-lg text-primary-light">
                  <Currency quantity={total} currency="MXN" />
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Controles de cantidad y eliminar */}
        <div className="flex flex-col sm:items-end items-center justify-center gap-4 my-auto">
          <div className="flex items-center gap-3 bg-gray-100 dark:bg-gray-700 rounded-lg p-2">
            <button
              className={`p-2 rounded-md transition-all duration-200 hover:bg-gray-200 dark:hover:bg-gray-600 ${
                disabled || qty <= 1 ? "opacity-50 cursor-not-allowed" : "hover:scale-110"
              }`}
              onClick={decQty}
              disabled={disabled || qty <= 1}
            >
              <MinusSmIcon className="h-5 w-5 text-gray-700 dark:text-gray-300" />
            </button>
            <div className="px-4 py-1 min-w-[3rem] text-center">
              <span className="font-bold md:text-lg text-base text-gray-800 dark:text-gray-200">
                {qty}
              </span>
            </div>
            <button
              className={`p-2 rounded-md transition-all duration-200 hover:bg-gray-200 dark:hover:bg-gray-600 ${
                disabled ? "opacity-50 cursor-not-allowed" : "hover:scale-110"
              }`}
              onClick={incQty}
              disabled={disabled}
            >
              <PlusIcon className="h-5 w-5 text-gray-700 dark:text-gray-300" />
            </button>
          </div>
          <button
            className={`flex items-center gap-2 button-red py-2 px-4 text-sm transition-all duration-300 hover:scale-105 ${
              disabled ? "opacity-50 cursor-not-allowed" : ""
            }`}
            onClick={removeItemFromCart}
            disabled={disabled}
          >
            <TrashIcon className="w-4 h-4" />
            <span>Eliminar</span>
          </button>
        </div>
      </div>
    </Fade>
  );
}

export default CartDish;
