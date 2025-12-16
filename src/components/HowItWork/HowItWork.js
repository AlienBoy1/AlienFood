import {
  ShoppingBagIcon,
  CreditCardIcon,
  TruckIcon,
} from "@heroicons/react/solid";
import Fade from "react-reveal/Fade";
import { useState } from "react";

function HowItWork() {
  const [hoveredStep, setHoveredStep] = useState(null);

  const steps = [
    {
      icon: ShoppingBagIcon,
      title: "Explora Productos",
      description: "Navega por nuestra amplia colección de figuras de acción, juguetes retro, consolas y coleccionables.",
      color: "from-indigo-500 to-purple-500",
    },
    {
      icon: CreditCardIcon,
      title: "Pago Seguro",
      description: "Completa tu pedido con información de envío y realiza el pago de forma segura.",
      color: "from-purple-500 to-pink-500",
    },
    {
      icon: TruckIcon,
      title: "Entrega Rápida",
      description: "Recibe tus productos cuidadosamente empaquetados directamente en tu puerta.",
      color: "from-pink-500 to-rose-500",
    },
  ];

  return (
    <div className="px-6 py-20 bg-white dark:bg-gray-900">
      <div className="max-w-screen-xl mx-auto">
        <Fade bottom>
          <h2 className="heading mb-4">Cómo Funciona</h2>
          <p className="text-center text-gray-600 dark:text-gray-400 max-w-2xl mx-auto mb-16">
            Proceso simple y rápido para obtener tus coleccionables favoritos
          </p>
        </Fade>
        <div className="mt-20">
          <div className="flex sm:justify-evenly text-center sm:gap-8 gap-12 flex-wrap sm:flex-row flex-col">
            {steps.map((step, index) => {
              const Icon = step.icon;
              const isHovered = hoveredStep === index;
              
              return (
                <Fade key={`step-${index}`} bottom delay={index * 150}>
                  <div
                    className="flex flex-col items-center sm:gap-6 gap-4 group cursor-pointer"
                    onMouseEnter={() => setHoveredStep(index)}
                    onMouseLeave={() => setHoveredStep(null)}
                  >
                    <div className={`relative p-6 rounded-2xl bg-gradient-to-br ${step.color} transform transition-all duration-300 ${
                      isHovered ? "scale-110 rotate-3 shadow-2xl" : "scale-100"
                    }`}>
                      <Icon className="sm:w-14 w-10 text-white mx-auto" />
                      <div className={`absolute -top-2 -right-2 w-8 h-8 rounded-full bg-white flex items-center justify-center font-bold text-sm text-primary-light transform transition-all duration-300 ${
                        isHovered ? "scale-125 rotate-12" : "scale-100"
                      }`}>
                        {index + 1}
                      </div>
                    </div>
                    <h3 className="font-semibold sm:text-2xl text-xl text-gray-800 dark:text-gray-200 transition-colors duration-300">
                      {step.title}
                    </h3>
                    <h4 className="max-w-xs mx-auto sm:text-base text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
                      {step.description}
                    </h4>
                  </div>
                </Fade>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

export default HowItWork;
