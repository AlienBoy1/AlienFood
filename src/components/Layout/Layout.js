import { useEffect } from "react";
import { useRouter } from "next/router";
import StorageService from "../../util/StorageService";
import { store } from "../../app/store";
import { hydrate } from "../../slices/cartSlice";
import Footer from "../Footer/Footer";
import Head from "next/head";
import Header from "../Header/Header";
import { useSession } from "next-auth/client";
import Loader from "react-loader-spinner";
import HeaderMobile from "../Header/HeaderMobile";
import HeaderDashboard from "../Header/HeaderDashboard";

function Layout({ children, admin, auth }) {
    const [session, loading] = useSession();
    const router = useRouter();

    useEffect(() => {
        store.subscribe(() => {
            StorageService.set("cart", JSON.stringify(store.getState().cart));
        });
        let cart = StorageService.get("cart");
        cart = cart ? JSON.parse(cart) : { items: [] };
        store.dispatch(hydrate(cart));
    }, []);

    useEffect(() => {
        if (!loading) {
            if (admin && !session?.admin) {
                router.push("/login");
            } else if (auth && !session) {
                router.push("/login");
            }
        }
    }, [loading, session, admin, auth, router]);

    return (
        <>
            <Head>
                <meta charSet="utf-8" />
                <meta httpEquiv="X-UA-Compatible" content="IE=edge" />
                <meta
                    name="viewport"
                    content="width=device-width,initial-scale=1.0,minimum-scale=1.0"
                />
                <title>TUNEL DEL TIEMPO - Figuras de Acción y Coleccionables</title>
                <meta
                    name="description"
                    content="Tienda de figuras de acción, juguetes retro, consolas clásicas y coleccionables de los 80s, 90s y 2000s. Marvel, DC, Dragon Ball Super y más."
                />
                {/* Favicon SVG tiene prioridad - funciona en navegadores modernos */}
                <link rel="icon" type="image/svg+xml" href="/img/favicons/favicon.svg" />
                {/* Fallbacks para navegadores antiguos */}
                <link rel="icon" type="image/png" sizes="32x32" href="/img/favicons/favicon.svg" />
                <link rel="icon" type="image/png" sizes="16x16" href="/img/favicons/favicon.svg" />
                <link rel="shortcut icon" href="/img/favicons/favicon.svg" />
                {/* Apple Touch Icon */}
                <link rel="apple-touch-icon" sizes="180x180" href="/img/tunel-logo-simple.svg" />
                <link rel="apple-touch-icon" href="/img/tunel-logo-simple.svg" />
                {/* Manifest y otros */}
                <link rel="manifest" href="/api/manifest" />
                <link rel="mask-icon" href="/img/favicons/favicon.svg" color="#6366f1" />
                <meta name="msapplication-TileColor" content="#da532c" />
                <meta
                    name="msapplication-config"
                    content="/img/favicons/browserconfig.xml"
                />
                <meta name="theme-color" content="#6366f1" />
            </Head>
            <div className="layout">
                {loading ? (
                    <div className="fixed inset-0 flex items-center justify-center bg-white z-50 loader">
                        <Loader type="TailSpin" color="#6366f1" />
                    </div>
                ) : admin ? (
                    session && session?.admin ? (
                        <>
                            <HeaderDashboard />
                            {children}
                            <Footer admin />
                        </>
                    ) : (
                        <div className="flex items-center justify-center heightFix">
                            <Loader type="TailSpin" color="#6366f1" />
                        </div>
                    )
                ) : auth ? (
                    session ? (
                        <>
                            <Header />
                            <HeaderMobile />
                            {children}
                            <Footer />
                        </>
                    ) : (
                        <div className="flex items-center justify-center heightFix">
                            <Loader type="TailSpin" color="#6366f1" />
                        </div>
                    )
                ) : (
                    <>
                        <Header />
                        <HeaderMobile />
                        {children}
                        <Footer />
                    </>
                )}
            </div>
        </>
    );
}

export default Layout;
