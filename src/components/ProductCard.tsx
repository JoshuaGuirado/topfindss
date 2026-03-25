import React, { useState } from "react";
import { Product } from "../types";
import { ExternalLink, Tag } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface ProductCardProps {
  product: Product;
}

const ProductCard: React.FC<ProductCardProps> = ({ product }) => {
  const [showOptions, setShowOptions] = useState(false);

  const handleClick = async () => {
    try {
      await fetch(`/api/products/${product.id}/click`, { method: "POST" });
    } catch (e) {
      console.error("Failed to track click", e);
    }
  };

  const getStoreNameFromUrl = (url: string) => {
    const lowerUrl = url.toLowerCase();
    if (lowerUrl.includes('amazon')) return 'Amazon';
    if (lowerUrl.includes('mercadolivre') || lowerUrl.includes('mercadolibre') || lowerUrl.includes('mlb-') || lowerUrl.includes('mlb')) return 'Mercado Livre';
    if (lowerUrl.includes('shopee')) return 'Shopee';
    if (lowerUrl.includes('aliexpress')) return 'AliExpress';
    if (lowerUrl.includes('magazineluiza') || lowerUrl.includes('magalu')) return 'Magalu';
    if (lowerUrl.includes('casasbahia')) return 'Casas Bahia';
    return 'Mercado Livre';
  };

  let links: { store?: string; url: string }[] = [];
  try {
    const parsed = JSON.parse(product.link_afiliado);
    if (Array.isArray(parsed)) {
      links = parsed.map(l => {
        const storeName = (l.store || '').toString().toLowerCase();
        const isGeneric = !l.store || storeName === 'principal' || storeName === 'ver oferta' || storeName === 'oferta' || storeName === 'ofertas';
        return {
          ...l,
          store: isGeneric ? getStoreNameFromUrl(l.url) : l.store
        };
      });
    } else {
      links = [{ store: getStoreNameFromUrl(product.link_afiliado), url: product.link_afiliado }];
    }
  } catch {
    links = [{ store: getStoreNameFromUrl(product.link_afiliado), url: product.link_afiliado }];
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -4 }}
      className="group bg-white rounded-2xl border border-neutral-200 overflow-hidden transition-all hover:shadow-xl hover:shadow-brand/5 flex flex-col h-full"
    >
      <div className="relative aspect-square overflow-hidden bg-white p-4">
        <img
          src={product.image || "https://picsum.photos/seed/product/400/400"}
          alt={product.name}
          className="w-full h-full object-contain transition-transform duration-500 group-hover:scale-105"
          referrerPolicy="no-referrer"
          loading="lazy"
        />
        {product.featured === 1 ? (
          <div className="absolute top-3 left-3 bg-brand text-white text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded-md flex items-center gap-1.5 shadow-lg">
            <Tag className="w-3 h-3" />
            Destaque
          </div>
        ) : product.tag_label && (
          <div
            className="absolute top-3 left-3 text-white text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded-md flex items-center gap-1.5 shadow-lg"
            style={{ backgroundColor: product.tag_color || "#0F172A" }}
          >
            <Tag className="w-3 h-3" />
            {product.tag_label}
          </div>
        )}
      </div>

      <div className="p-3 sm:p-5 flex flex-col flex-1">
        <div className="mb-2">
          <p className="text-[8px] sm:text-[10px] font-bold text-neutral-400 uppercase tracking-widest mb-1">
            {product.category_name} • {product.subcategory_name}
          </p>
          <h3 className="text-xs sm:text-sm md:text-base font-bold text-neutral-900 line-clamp-2 group-hover:text-brand transition-colors leading-tight min-h-[2rem] sm:min-h-[2.5rem]">
            {product.name}
          </h3>
        </div>

        <p className="text-[10px] sm:text-sm text-neutral-500 line-clamp-2 mb-3 sm:mb-4 leading-relaxed">
          {product.description}
        </p>

        <div className="mt-auto pt-3 sm:pt-4 flex flex-col gap-2 sm:gap-3 border-t border-neutral-100">
          <div className="flex flex-col">
            {product.price_original && (
              <span className="text-[8px] sm:text-[10px] text-neutral-400 font-medium line-through">
                De R$ {product.price_original.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
              </span>
            )}
            {product.price && (
              <div className="flex items-center justify-between">
                <div className="flex items-baseline gap-1 sm:gap-1.5">
                  <span className="text-[10px] sm:text-xs text-neutral-500 font-medium uppercase tracking-wider">
                    Por
                  </span>
                  <span className="text-base sm:text-xl font-black text-brand">
                    R$ {product.price.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </span>
                </div>
                {links[0]?.store && (
                  <span className="text-[8px] sm:text-[10px] font-bold text-neutral-400 bg-neutral-100 px-2 py-0.5 rounded-full uppercase tracking-widest">
                    {links[0].store}
                  </span>
                )}
              </div>
            )}
          </div>

          {links.length > 1 ? (
            <div className="relative w-full">
              <button
                onClick={() => setShowOptions(!showOptions)}
                className="w-full bg-brand text-white text-xs sm:text-sm font-bold py-2 sm:py-3.5 px-2 sm:px-4 rounded-xl flex items-center justify-center gap-1.5 sm:gap-2 hover:bg-brand/90 transition-all active:scale-95 shadow-lg shadow-brand/10"
              >
                Ofertas
                <ExternalLink className="w-3 h-3 sm:w-4 sm:h-4" />
              </button>

              <AnimatePresence>
                {showOptions && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    className="absolute bottom-[calc(100%+0.5rem)] left-0 w-full bg-white rounded-xl shadow-xl border border-neutral-200 overflow-hidden z-20"
                  >
                    {links.map((link, idx) => (
                      <a
                        key={idx}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => {
                          handleClick();
                          setShowOptions(false);
                        }}
                        className="flex items-center justify-between px-3 sm:px-4 py-2 sm:py-3 text-xs sm:text-sm font-bold text-neutral-700 hover:bg-brand/5 hover:text-brand border-b border-neutral-100 last:border-b-0 transition-colors"
                      >
                        {link.store || 'Oferta'}
                        <ExternalLink className="w-3 h-3 sm:w-3.5 sm:h-3.5 opacity-50" />
                      </a>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ) : (
            <a
              href={links[0]?.url || product.link_afiliado}
              target="_blank"
              rel="noopener noreferrer"
              onClick={handleClick}
              className="w-full bg-brand text-white text-xs sm:text-sm font-bold py-2 sm:py-3.5 px-2 sm:px-4 rounded-xl flex items-center justify-center gap-1.5 sm:gap-2 hover:bg-brand/90 transition-all active:scale-95 shadow-lg shadow-brand/10"
            >
              Ver Oferta
              <ExternalLink className="w-3 h-3 sm:w-4 sm:h-4" />
            </a>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default ProductCard;
