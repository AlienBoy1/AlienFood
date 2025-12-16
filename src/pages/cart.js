import { useDispatch, useSelector } from "react-redux";
import Currency from "react-currency-formatter";
import { useSession } from "next-auth/client";
import { loadStripe } from "@stripe/stripe-js";
import axios from "axios";
import { useRouter } from "next/router";
import { emptyCart, selectItems, selectTotal } from "../slices/cartSlice";
import CartDish from "../components/CartDish/CartDish";
import { CreditCardIcon, ShoppingBagIcon, TrashIcon } from "@heroicons/react/solid";
import { useState } from "react";
import Head from "next/head";
import Image from "next/image";
import BackButton from "../components/BackButton/BackButton";
import Fade from "react-reveal/Fade";

const stripePromise = loadStripe(process.env.stripe_public_key);

function Cart() {
  const items = useSelector(selectItems);
  const total = useSelector(selectTotal);
  const [session] = useSession();
  const [disabled, setDisabled] = useState(false);
  const dispatch = useDispatch();
  const router = useRouter();

  const createCheckoutSession = async () => {
    setDisabled(true);
    try {
      const stripe = await stripePromise;
      const checkoutSession = await axios.post("/api/create-checkout-session", {
        items: items,
        email: session.user.email,
      });
      const result = await stripe.redirectToCheckout({
        sessionId: checkoutSession.data.id,
      });
      if (result.error) {
        alert(result.error.message);
        console.error(result.error.message);
      }
    } catch (err) {
      console.error(err);
      alert(err);
    }
    setDisabled(false);
  };

  return (
    <>
      <Head>
        <title>TUNEL DEL TIEMPO | Carrito</title>
      </Head>
      <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 py-6 sm:py-10 px-3 sm:px-6 min-h-screen">
        <main className="max-w-screen-xl mx-auto">
          <div className="flex items-center gap-4 mb-6">
            <BackButton />
          </div>
          {items?.length ? (
            <Fade bottom>
              <div className="my-6 shadow-xl rounded-xl overflow-hidden">
                <div className="flex flex-col md:p-8 p-6 bg-white dark:bg-gray-800">
                  <div className="flex items-center gap-3 mb-6 pb-4 border-b-2 border-gray-200 dark:border-gray-700">
                    <ShoppingBagIcon className="w-8 h-8 text-primary-light" />
                    <h1 className="sm:text-3xl text-2xl font-bold text-gray-800 dark:text-gray-200">
                      Carrito de Compras
                    </h1>
                  </div>
                  <div className="flex justify-between items-center py-4 bg-gradient-to-r from-indigo-50 to-purple-50 dark:from-gray-700 dark:to-gray-700 rounded-lg px-4 mb-6">
                    <span className="font-semibold text-lg text-gray-700 dark:text-gray-300">
                      Artículos en tu carrito:
                      <span className="font-bold text-primary-light ml-2 text-xl">
                        {items?.length}
                      </span>
                    </span>
                    <button
                      className={`flex items-center gap-2 button-red py-2 px-6 transition-all duration-300 hover:scale-105 ${
                        disabled ? "opacity-50 cursor-not-allowed" : ""
                      }`}
                      onClick={() => {
                        if (confirm("¿Estás seguro de vaciar el carrito?")) {
                          dispatch(emptyCart());
                        }
                      }}
                      disabled={disabled}
                    >
                      <TrashIcon className="w-5 h-5" />
                      <span>Vaciar Carrito</span>
                    </button>
                  </div>
                  <div className="space-y-4">
                    {items.map((item, i) => (
                      <CartDish
                        key={`cart-dish-${item?._id}`}
                        _id={item?._id}
                        title={item?.title}
                        price={item?.price}
                        description={item?.description}
                        category={item?.category}
                        image={item?.image}
                        qty={item?.qty}
                        border={i !== items?.length - 1}
                        disabled={disabled}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </Fade>
          ) : (
            <Fade bottom>
              <div className="flex items-center justify-center w-full px-6 lg:py-20 sm:py-10 py-4">
                <div className="text-center md:max-w-none sm:w-auto mx-auto max-w-xs w-4/5">
                  <div className="relative">
                    <Image
                      src="/img/empty_cart.svg"
                      alt="Carrito vacío"
                      width={350}
                      height={350}
                      objectFit="contain"
                      className="opacity-80"
                    />
                  </div>
                  <h3 className="lg:text-3xl text-2xl font-bold mt-6 text-gray-800 dark:text-gray-200">
                    Tu carrito está vacío
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2 mb-6">
                    ¡Agrega algunos productos increíbles!
                  </p>
                  <button
                    className="button px-8 py-3 text-lg"
                    onClick={() => router.push("/#menu")}
                  >
                    Explorar Productos
                  </button>
                </div>
              </div>
            </Fade>
          )}
          {items?.length ? (
            <Fade bottom delay={200}>
              <div className="flex flex-col bg-white dark:bg-gray-800 md:p-10 py-8 px-6 shadow-2xl rounded-xl md:text-xl sm:text-lg text-base my-10 border-2 border-primary-light/20">
                <div className="flex justify-between items-center mb-6 pb-4 border-b-2 border-gray-200 dark:border-gray-700">
                  <h2 className="font-semibold text-gray-700 dark:text-gray-300">
                    Resumen del Pedido
                  </h2>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {items.length} {items.length === 1 ? "artículo" : "artículos"}
                  </span>
                </div>
                <div className="flex justify-between items-center mb-6">
                  <span className="font-medium text-gray-700 dark:text-gray-300">
                    Subtotal:
                  </span>
                  <span className="font-bold text-2xl text-primary-light">
                    <Currency quantity={total} currency="MXN" />
                  </span>
                </div>
                {session ? (
                  <button
                    role="link"
                    className={`button mt-6 flex items-center justify-center gap-3 lg:text-lg text-base py-4 transition-all duration-300 hover:scale-105 hover:shadow-xl ${
                      disabled ? "opacity-50 cursor-not-allowed" : ""
                    }`}
                    onClick={!disabled ? createCheckoutSession : () => {}}
                    disabled={disabled}
                  >
                    <CreditCardIcon className="sm:w-6 w-5" />
                    <span>Continuar con el Pago</span>
                  </button>
                ) : (
                  <button
                    role="link"
                    className="button mt-6 lg:text-lg text-base py-4 transition-all duration-300 hover:scale-105"
                    onClick={() => router.push("/login")}
                  >
                    Iniciar Sesión para Continuar
                  </button>
                )}
              </div>
            </Fade>
          ) : null}
        </main>
      </div>
    </>
  );
}

export default Cart;
