import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(supabaseUrl!, supabaseKey!);

async function listTables() {
  const { data, error } = await supabase
    .from('_rpc_call_to_list_tables_or_something') // No direct way to list tables via client without RPC
    .select('*');
  
  // Actually, we can just try to select from 'users' as a canary
  const { data: users, error: userError } = await supabase.from('users').select('*').limit(1);
  console.log("Users connection:", userError ? userError.message : "Success");
}

listTables();
