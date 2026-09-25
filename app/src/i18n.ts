import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import es from "./locales/es";
import en from "./locales/en";

const stored = localStorage.getItem("netgrip-lang");
const browser = navigator.language.startsWith("es") ? "es" : "en";

i18n.use(initReactI18next).init({
  resources: { es: { translation: es }, en: { translation: en } },
  lng: stored || browser,
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

// The document's lang has to follow the active language. Served as a static
// "es" it told every browser the page was Spanish, so an English UI was
// offered for translation on every load - and accepting that runs the page
// through a translator, which rewrites the data too: interface names,
// hostnames and SSIDs are not words to translate.
const applyDocLang = (lng?: string) => {
  const l = (lng ?? i18n.language ?? "en").slice(0, 2).toLowerCase();
  document.documentElement.lang = l === "es" ? "es" : "en";
};
applyDocLang();

i18n.on("languageChanged", (lng) => {
  localStorage.setItem("netgrip-lang", lng);
  applyDocLang(lng);
});

export default i18n;
