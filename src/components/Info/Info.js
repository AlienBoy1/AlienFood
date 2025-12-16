import {
  ClockIcon,
  LocationMarkerIcon,
  PhoneIcon,
} from "@heroicons/react/solid";
import Fade from "react-reveal/Fade";
import { useState } from "react";

function Info() {
  const [hoveredItem, setHoveredItem] = useState(null);

  const infoItems = [
    {
      icon: ClockIcon,
      title: "Lun - Dom: 9am - 9pm",
      subtitle: "Horario de Atención",
      color: "from-indigo-500 to-purple-500",
    },
    {
      icon: LocationMarkerIcon,
      title: "Envío a Todo México",
      subtitle: "Obtener Direcciones",
      color: "from-purple-500 to-pink-500",
    },
    {
      icon: PhoneIcon,
      title: "+52 55 1234 5678",
      subtitle: "Llamar Ahora",
      color: "from-pink-500 to-rose-500",
    },
  ];

  return (
    <div className="px-6 py-20 bg-gradient-to-br from-indigo-50 via-purple-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      <div className="flex justify-evenly mx-auto max-w-screen-lg flex-wrap sm:gap-8 gap-10 sm:flex-row flex-col">
        {infoItems.map((item, index) => {
          const Icon = item.icon;
          const isHovered = hoveredItem === index;

          return (
            <Fade key={`info-${index}`} bottom delay={index * 100}>
              <div
                className="flex flex-col items-center gap-4 p-6 rounded-xl bg-white dark:bg-gray-800 shadow-lg hover:shadow-2xl transform transition-all duration-300 cursor-pointer group min-w-[200px]"
                onMouseEnter={() => setHoveredItem(index)}
                onMouseLeave={() => setHoveredItem(null)}
              >
                <div className={`p-4 rounded-full bg-gradient-to-br ${item.color} transform transition-all duration-300 ${
                  isHovered ? "scale-110 rotate-12" : "scale-100"
                }`}>
                  <Icon className="lg:w-8 w-6 text-white" />
                </div>
                <h3 className="font-semibold text-lg text-gray-800 dark:text-gray-200 transition-colors duration-300">
                  {item.title}
                </h3>
                <h4 className="text-sm text-gray-600 dark:text-gray-400">
                  {item.subtitle}
                </h4>
              </div>
            </Fade>
          );
        })}
      </div>
    </div>
  );
}

export default Info;
