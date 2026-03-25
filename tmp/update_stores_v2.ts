import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve('.env') });

const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseKey = process.env.SUPABASE_ANON_KEY!;

const supabase = createClient(supabaseUrl, supabaseKey);

const getStoreNameFromUrl = (url: string) => {
  if (!url) return 'Principal';
  const lowerUrl = url.toLowerCase();
  if (lowerUrl.includes('amazon')) return 'Amazon';
  if (lowerUrl.includes('mercadolivre') || lowerUrl.includes('mlb')) return 'Mercado Livre';
  if (lowerUrl.includes('shopee')) return 'Shopee';
  if (lowerUrl.includes('aliexpress')) return 'AliExpress';
  if (lowerUrl.includes('magazineluiza') || lowerUrl.includes('magalu')) return 'Magalu';
  if (lowerUrl.includes('casasbahia')) return 'Casas Bahia';
  return 'Principal';
};

async function run() {
  console.log("Starting DB update...");
  // Use .from('products') directly as Supabase client defaults to public schema
  const { data: products, error } = await supabase.from('products').select('*');

  if (error) {
    console.error("Fetch Error:", error);
    return;
  }

  console.log(`Checking ${products.length} products...`);
  
  for (const p of products) {
    let links = [];
    let updated = false;
    try {
      const parsed = JSON.parse(p.link_afiliado);
      if (Array.isArray(parsed)) {
        links = parsed.map(l => {
          if (!l.store || l.store === 'Principal' || l.store === 'Oferta') {
            const detected = getStoreNameFromUrl(l.url);
            if (detected !== 'Principal') {
                l.store = detected;
                updated = true;
            }
          }
          return l;
        });
      } else {
        const detected = getStoreNameFromUrl(p.link_afiliado);
        links = [{ store: detected, url: p.link_afiliado }];
        updated = true;
      }
    } catch {
       const detected = getStoreNameFromUrl(p.link_afiliado);
       links = [{ store: detected, url: p.link_afiliado }];
       updated = true;
    }

    if (updated) {
      console.log(`Updating ${p.id} -> ${JSON.stringify(links)}`);
      const { error: updErr } = await supabase.from('products').update({ link_afiliado: JSON.stringify(links) }).eq('id', p.id);
      if (updErr) console.error(`Error updating ${p.id}:`, updErr);
    }
  }
  console.log("Done.");
}

run();
