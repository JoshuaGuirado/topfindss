import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("Missing ENV vars");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

async function test() {
  console.log("Testing Categories...");
  const { data: cats, error: catError } = await supabase.from('categories').select('*');
  if (catError) console.error("Cat Error:", catError.message);
  else console.log("Cats found:", cats.length);

  console.log("Testing Products...");
  const { data: prods, error: prodError } = await supabase.from('products').select('*').limit(1);
  if (prodError) console.error("Prod Error:", prodError.message);
  else console.log("Products found:", prods.length);
}

test();
