import { useState, useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { Category, Product } from "../types";
import ProductCard from "../components/ProductCard";
import { ShoppingBag, Sparkles, TrendingUp, Filter } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface HomeProps {
  categories: Category[];
}

export default function Home({ categories }: HomeProps) {
  const [searchParams] = useSearchParams();
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  // Filter States
  const [maxPrice, setMaxPrice] = useState<number | "">("");
  const [minPrice, setMinPrice] = useState<number | "">("");
  const [filterCategory, setFilterCategory] = useState<string>("");
  const [filterStore, setFilterStore] = useState<string>("");
  const [showFilters, setShowFilters] = useState(false);

  const categoryId = searchParams.get("category");
  const subcategoryId = searchParams.get("subcategory");
  const search = searchParams.get("search");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (categoryId) params.set("category", categoryId);
    if (subcategoryId) params.set("subcategory", subcategoryId);
    if (search) params.set("search", search);

    fetch(`/api/products?${params.toString()}`)
      .then(res => res.ok ? res.json() : [])
      .then(data => {
        setProducts(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(err => {
        console.error("API Fetch Error:", err);
        setProducts([]);
        setLoading(false);
      });
  }, [categoryId, subcategoryId, search]);

  const getStoreNameFromUrl = (url: string) => {
    if (!url) return 'Principal';
    const lowerUrl = url.toLowerCase();
    // Amazon
    if (lowerUrl.includes('amazon') || lowerUrl.includes('amzn.')) return 'Amazon';
    // Mercado Livre
    if (lowerUrl.includes('mercadolivre') || lowerUrl.includes('mercadolibre') || lowerUrl.includes('mlb-') || lowerUrl.includes('mlb')) return 'Mercado Livre';
    // Shopee
    if (lowerUrl.includes('shopee')) return 'Shopee';
    // AliExpress
    if (lowerUrl.includes('aliexpress') || lowerUrl.includes('ali.')) return 'AliExpress';
    // Magalu
    if (lowerUrl.includes('magazineluiza') || lowerUrl.includes('magalu')) return 'Magalu';
    // Casas Bahia
    if (lowerUrl.includes('casasbahia')) return 'Casas Bahia';
    
    return 'Mercado Livre';
  };

  const availableStores = useMemo(() => {
    if (!Array.isArray(products)) return [];
    const stores = new Set<string>();
    products.forEach(p => {
      try {
        const parsed = JSON.parse(p.link_afiliado);
        if (Array.isArray(parsed)) {
          parsed.forEach((link: any) => {
            const rawName = link.store;
            const name = (!rawName || rawName === 'Principal' || rawName === 'Ver Oferta' || rawName === 'Oferta') 
              ? getStoreNameFromUrl(link.url) 
              : rawName;
            if (name && name !== 'Principal') stores.add(name);
          });
        } else {
          const name = getStoreNameFromUrl(p.link_afiliado);
          if (name && name !== 'Principal') stores.add(name);
        }
      } catch {
        const name = getStoreNameFromUrl(p.link_afiliado);
        if (name && name !== 'Principal') stores.add(name);
      }
    });
    return Array.from(stores).sort();
  }, [products]);

  const filteredProducts = useMemo(() => {
    if (!Array.isArray(products)) return [];
    return products.filter(p => {
      // Price filters
      if (minPrice !== "" && p.price !== null && p.price < minPrice) return false;
      if (maxPrice !== "" && p.price !== null && p.price > maxPrice) return false;

      // Category filter (Frontend side, additive to URL param)
      if (filterCategory && p.category_id.toString() !== filterCategory) return false;

      // Store filter
      if (filterStore) {
        let hasStore = false;
        try {
          const parsed = JSON.parse(p.link_afiliado);
          if (Array.isArray(parsed)) {
            hasStore = parsed.some((link: any) => {
              const rawName = link.store;
              const name = (!rawName || rawName === 'Principal' || rawName === 'Ver Oferta' || rawName === 'Oferta') 
                ? getStoreNameFromUrl(link.url) 
                : rawName;
              return name === filterStore;
            });
          } else {
            hasStore = getStoreNameFromUrl(p.link_afiliado) === filterStore;
          }
        } catch {
          hasStore = getStoreNameFromUrl(p.link_afiliado) === filterStore;
        }
        if (!hasStore) return false;
      }

      return true;
    });
  }, [products, minPrice, maxPrice, filterCategory, filterStore]);

  const featuredProducts = filteredProducts.filter(p => p.featured === 1);
  const regularProducts = filteredProducts.filter(p => p.featured !== 1);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="w-8 h-8 border-4 border-brand border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 sm:gap-8">
      {/* Price Filters Toggle */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-neutral-200 rounded-lg shadow-sm hover:bg-neutral-50 text-sm font-medium transition-colors"
        >
          <Filter className="w-4 h-4" />
          Filtros
        </button>
      </div>

      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="p-4 bg-white border border-neutral-200 rounded-2xl flex flex-wrap gap-4 items-end shadow-sm mt-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Preço Mínimo</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500 font-medium">R$</span>
                  <input
                    type="number"
                    placeholder="0,00"
                    value={minPrice}
                    onChange={(e) => setMinPrice(e.target.value ? Number(e.target.value) : "")}
                    className="pl-8 pr-4 py-2 bg-neutral-100 border-none rounded-lg text-sm focus:ring-2 focus:ring-brand/20 w-32"
                  />
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Preço Máximo</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500 font-medium">R$</span>
                  <input
                    type="number"
                    placeholder=""
                    value={maxPrice}
                    onChange={(e) => setMaxPrice(e.target.value ? Number(e.target.value) : "")}
                    className="pl-8 pr-4 py-2 bg-neutral-100 border-none rounded-lg text-sm focus:ring-2 focus:ring-brand/20 w-32"
                  />
                </div>
              </div>
              <div className="flex flex-col gap-1.5 w-full sm:w-auto flex-1 min-w-[140px]">
                <label className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Categoria</label>
                <select
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value)}
                  className="w-full bg-neutral-100 border-none rounded-lg text-sm py-2 px-3 focus:ring-2 focus:ring-brand/20 outline-none"
                >
                  <option value="">Todas</option>
                  {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>

              {availableStores.length > 0 && (
                <div className="flex flex-col gap-1.5 w-full sm:w-auto flex-1 min-w-[140px]">
                  <label className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Loja</label>
                  <select
                    value={filterStore}
                    onChange={(e) => setFilterStore(e.target.value)}
                    className="w-full bg-neutral-100 border-none rounded-lg text-sm py-2 px-3 focus:ring-2 focus:ring-brand/20 outline-none"
                  >
                    <option value="">Qualquer Loja</option>
                    {availableStores.map(store => <option key={store} value={store}>{store}</option>)}
                  </select>
                </div>
              )}
            </div>

            <div className="flex justify-end px-4 pb-4">
              {(minPrice !== "" || maxPrice !== "" || filterCategory !== "" || filterStore !== "") && (
                <button
                  onClick={() => { setMinPrice(""); setMaxPrice(""); setFilterCategory(""); setFilterStore(""); }}
                  className="px-4 py-2 text-sm text-neutral-500 hover:text-red-500 font-bold transition-colors"
                >
                  Limpar Filtros
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Hero / Featured Section */}
      {!search && !categoryId && !subcategoryId && featuredProducts.length > 0 && (
        <section>
          <div className="flex items-center gap-3 mb-6">
            <div>
              <h2 className="text-2xl font-black tracking-tight">Destaques</h2>
              <p className="text-sm text-neutral-500">As melhores ofertas selecionadas para você</p>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-3 md:gap-4">
            {featuredProducts.map(product => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        </section>
      )}

      {/* Main Catalog */}
      <section>
        <div className="flex items-center gap-3 mb-6">
          <div>
            <h2 className="text-2xl font-black tracking-tight">
              {search ? `Resultados para "${search}"` : categoryId ? "Catálogo de Produtos" : "Todas as Ofertas"}
            </h2>
            <p className="text-sm text-neutral-500">
              {filteredProducts.length} {filteredProducts.length === 1 ? "produto encontrado" : "produtos encontrados"}
            </p>
          </div>
        </div>

        {filteredProducts.length === 0 ? (
          <div className="bg-white border border-neutral-200 rounded-3xl p-12 text-center flex flex-col items-center gap-4">
            <div className="w-16 h-16 bg-neutral-100 rounded-full flex items-center justify-center text-neutral-400">
              <ShoppingBag className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-lg font-bold">Nenhum produto encontrado</h3>
              <p className="text-neutral-500 max-w-xs mx-auto">Tente ajustar seus filtros ou buscar por outro termo.</p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-3 md:gap-4">
            {(!search && !categoryId && !subcategoryId ? regularProducts : filteredProducts).map(product => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
