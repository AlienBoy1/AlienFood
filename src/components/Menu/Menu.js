import Dish from "../Dish/Dish";
import { useState } from "react";
import { AdjustmentsIcon, SparklesIcon } from "@heroicons/react/outline";
import Fade from "react-reveal/Fade";

function Menu({ dishes, categories }) {
  const safeDishes = Array.isArray(dishes) ? dishes : [];
  const safeCategories = Array.isArray(categories) ? categories : [];
  
  const [categoryActive, setCategoryActive] = useState("all");
  const [filteredDishes, setFilteredDishes] = useState(safeDishes);

  const activeCategoryHandler = (category) => {
    if (category === "all" || categoryActive === category) {
      setCategoryActive("all");
      setFilteredDishes(safeDishes);
      return;
    }
    setCategoryActive(category);
    filterDishes(category);
  };

  const filterDishes = (category) => {
    setFilteredDishes(
      safeDishes.filter((dish) => dish?.category === category)
    );
  };

  return (
    <div className="w-full py-12 sm:py-20 px-4 sm:px-6 bg-gradient-to-b from-gray-50 to-white dark:from-gray-900 dark:to-gray-800 mt-10" id="menu">
      <Fade bottom>
        <div className="text-center mb-12">
          <h2 className="heading lg:mb-4 sm:mb-3 mb-2 mt-4">
            Explora Nuestra Colección
          </h2>
          <p className="text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            Descubre figuras de acción, juguetes retro, consolas clásicas y mucho más
          </p>
        </div>
      </Fade>
      
      {/* Filtros de categorías */}
      <div className="flex items-center w-full max-w-screen-xl sm:mb-20 mb-16 gap-4 mx-auto overflow-x-auto hideScrollBar capitalize text-sm font-medium pb-4">
        <div className="flex items-center gap-2 text-primary-light">
          <AdjustmentsIcon className="w-6 h-6" />
          <span className="font-semibold">Filtros:</span>
        </div>
        <div
          className={`py-3 px-6 bg-white dark:bg-gray-800 text-center rounded-lg hover:shadow-lg transition-all cursor-pointer ease-in-out duration-300 shadow-md transform hover:scale-105 ${
            categoryActive === "all"
              ? "bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg scale-105"
              : "text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
          }`}
          onClick={() => activeCategoryHandler("all")}
        >
          <span className="font-medium">Todos</span>
        </div>
        {safeCategories.map((category, i) => (
          <Fade key={`category-${i}`} right delay={i * 50}>
            <div
              className={`py-3 px-6 bg-white dark:bg-gray-800 text-center whitespace-nowrap rounded-lg hover:shadow-lg transition-all cursor-pointer ease-in-out duration-300 shadow-md transform hover:scale-105 ${
                categoryActive === category?.name
                  ? "bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg scale-105"
                  : "text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
              }`}
              onClick={() => activeCategoryHandler(category?.name)}
            >
              <span className="font-medium">{category?.name}</span>
            </div>
          </Fade>
        ))}
      </div>

      {/* Grid de productos */}
      {safeDishes.length === 0 ? (
        <div className="text-center py-20">
          <SparklesIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-400 text-lg">
            No hay productos disponibles en este momento
          </p>
        </div>
      ) : (
        <div className="grid grid-flow-row-dense sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 grid-cols-1 mx-auto max-w-screen-xl gap-6">
          {(categoryActive === "all" ? safeDishes : filteredDishes).map(
            ({ _id, title, price, description, category, image }, index) => (
              <Dish
                key={`dish-${_id}`}
                _id={_id}
                title={title}
                price={price}
                description={description}
                category={category}
                image={image}
              />
            )
          )}
        </div>
      )}
    </div>
  );
}

export default Menu;
