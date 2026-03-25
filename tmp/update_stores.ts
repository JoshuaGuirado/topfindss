import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import path from 'path';

// Load .env from project root
dotenv.config({ path: path.resolve('C:/Users/joshu/Downloads/top findss original/topfindss-main/.env') });

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseKey = process.env.SUPABASE_ANON_KEY!;

if (!supabaseUrl || !supabaseKey) {
  console.error("Missing Supabase credentials in .env");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

const getStoreNameFromUrl = (url: string) => {
  const lowerUrl = url.toLowerCase();
  if (lowerUrl.includes('amazon')) return 'Amazon';
  if (lowerUrl.includes('mercadolivre') || lowerUrl.includes('mlb')) return 'Mercado Livre';
  if (lowerUrl.includes('shopee')) return 'Shopee';
  if (lowerUrl.includes('aliexpress')) return 'AliExpress';
  if (lowerUrl.includes('magazineluiza') || lowerUrl.includes('magalu')) return 'Magalu';
  if (lowerUrl.includes('casasbahia')) return 'Casas Bahia';
  return 'Principal';
};

async function updateProducts() {
  const { data: products, error } = await supabase.from('products').select('id, link_afiliado');
  
  if (error) {
    console.error("Error fetching products:", error);
    return;
  }

  console.log(`Found ${products.length} products to check.`);

  for (const product of products) {
    let links: any[] = [];
    let updated = false;

    try {
      const parsed = JSON.parse(product.link_afiliado);
      if (Array.isArray(parsed)) {
        links = parsed.map(link => {
          if (!link.store || link.store === "Principal" || link.store === "Oferta" || link.store === "Ver Oferta") {
            const detectedStore = getStoreNameFromUrl(link.url);
            if (detectedStore !== "Principal") {
               link.store = detectedStore;
               updated = true;
            }
          }
          return link;
        });
      } else {
        const detectedStore = getStoreNameFromUrl(product.link_afiliado);
        links = [{ store: detectedStore, url: product.link_afiliado }];
        updated = true;
      }
    } catch {
      const detectedStore = getStoreNameFromUrl(product.link_afiliado);
      links = [{ store: detectedStore, url: product.link_afiliado }];
      updated = true;
    }

    if (updated) {
      console.log(`Updating product ${product.id} with stores: ${links.map(l => l.store).join(', ')}`);
      const { error: updateError } = await supabase
        .from('products')
        .update({ link_afiliado: JSON.stringify(links) })
        .eq('id', product.id);
      
      if (updateError) console.error(`Error updating ${product.id}:`, updateError);
    }
  }

  console.log("Finished updating products.");
}

updateProducts();
