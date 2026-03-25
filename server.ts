import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import axios from "axios";
import * as cheerio from "cheerio";
import { GoogleGenAI } from "@google/genai";
dotenv.config(); // Load before everything 

import { createClient } from "@supabase/supabase-js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error("SUPABASE_URL e SUPABASE_ANON_KEY precisam estar configurados no .env");
  process.exit(1);
}

export const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

async function startServer() {
  const app = express();
  app.use(express.json());

  // Auth Middleware
  const authenticate = async (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded: any = jwt.verify(token, JWT_SECRET);

      const { data: user, error } = await supabase
        .from('users')
        .select('id, email, is_admin')
        .eq('id', decoded.id)
        .single();

      if (error || !user) {
        return res.status(401).json({ error: "User not found" });
      }
      req.user = user;
      next();
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  const requireAdmin = (req: any, res: any, next: any) => {
    if (!req.user || req.user.is_admin !== 1) {
      return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
  };

  // API Routes
  app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin === 1 } });
  });

  app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const { data: valUser } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
      if (valUser) return res.status(400).json({ error: "E-mail já cadastrado" });

      const hashedPassword = bcrypt.hashSync(password, 10);
      const { data: result, error } = await supabase
        .from('users')
        .insert([{ name, email, password: hashedPassword, is_admin: 0 }])
        .select()
        .single();

      if (error) throw error;

      const token = jwt.sign({ id: result.id }, JWT_SECRET, { expiresIn: "1d" });
      res.json({ token, user: { id: result.id, name, email, is_admin: false } });
    } catch (e) {
      res.status(400).json({ error: "Erro ao registrar usuário" });
    }
  });

  app.get("/api/auth/me", authenticate, async (req: any, res) => {
    const { data: user, error } = await supabase.from('users').select('id, name, email, is_admin').eq('id', req.user.id).single();
    if (error || !user) return res.status(404).json({ error: "User not found" });
    res.json({ user: { ...user, is_admin: user.is_admin === 1 } });
  });

  // Users Management (Admin Only)
  app.get("/api/admin/users", authenticate, requireAdmin, async (req, res) => {
    const { data: users, error } = await supabase.from('users').select('id, name, email, is_admin').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: "Failed to fetch users" });
    res.json(users);
  });

  app.post("/api/admin/users/:id/toggle-admin", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { is_admin } = req.body;

    // Prevent removing master admin
    if (Number(id) === 1 || is_admin === false) {
      const { data: user } = await supabase.from('users').select('email').eq('id', id).single();
      if (user && user.email === "topfinds.dj2@gmail.com") {
        return res.status(400).json({ error: "Cannot modify access for master admin" });
      }
    }

    const { error } = await supabase.from('users').update({ is_admin: is_admin ? 1 : 0 }).eq('id', id);
    if (error) return res.status(500).json({ error: "Update failed" });
    res.json({ success: true });
  });

  app.post("/api/admin/users/create", authenticate, requireAdmin, async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const { data: valUser } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
      if (valUser) return res.status(400).json({ error: "E-mail já está em uso" });

      const hashedPassword = bcrypt.hashSync(password, 10);
      const { error } = await supabase.from('users').insert([{ name, email, password: hashedPassword, is_admin: 1 }]);
      if (error) throw error;

      res.status(201).json({ message: "Administrador criado com sucesso" });
    } catch (e) {
      res.status(400).json({ error: "Erro ao criar novo administrador" });
    }
  });

  // Categories & Subcategories
  // Categories & Subcategories
  app.get("/api/categories", async (req, res) => {
    const { data: cats, error: catError } = await supabase.from('categories').select('*');
    if (catError) {
      console.error("❌ ERRO AO BUSCAR CATEGORIAS:", catError.message);
      return res.status(500).json({ error: "Failed to fetch categories", details: catError.message });
    }

    const { data: subcats, error: subError } = await supabase.from('subcategories').select('*').order('order_index', { ascending: true });
    if (subError) return res.status(500).json({ error: "Failed to fetch subcategories" });

    const result = cats.map((cat: any) => ({
      ...cat,
      subcategories: subcats.filter((sub: any) => sub.category_id === cat.id)
    }));
    res.json(result);
  });

  app.post("/api/categories", authenticate, requireAdmin, async (req, res) => {
    const { name } = req.body;
    try {
      const { data, error } = await supabase.from('categories').insert([{ name }]).select().single();
      if (error) throw error;
      res.json({ id: data.id });
    } catch (e) {
      res.status(400).json({ error: "Category already exists" });
    }
  });

  app.put("/api/categories/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    const { error } = await supabase.from('categories').update({ name }).eq('id', id);
    if (error) return res.status(400).json({ error: "Update failed" });
    res.json({ success: true });
  });

  app.delete("/api/categories/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('categories').delete().eq('id', id);
    if (error) return res.status(400).json({ error: "Delete failed" });
    res.json({ success: true });
  });

  app.post("/api/subcategories", authenticate, requireAdmin, async (req, res) => {
    const { name, category_id } = req.body;
    try {
      const { data: maxOrder } = await supabase
        .from('subcategories')
        .select('order_index')
        .eq('category_id', category_id)
        .order('order_index', { ascending: false })
        .limit(1)
        .single();

      const nextOrder = (maxOrder?.order_index || 0) + 1;

      const { data, error } = await supabase
        .from('subcategories')
        .insert([{ name, category_id, order_index: nextOrder }])
        .select()
        .single();

      if (error) throw error;
      res.json({ id: data.id });
    } catch (e) {
      res.status(400).json({ error: "Subcategory already exists in this category" });
    }
  });

  app.post("/api/subcategories/reorder", authenticate, requireAdmin, async (req, res) => {
    const { subcategories } = req.body; // Array of { id, order_index }

    // Supabase does not have true batch update, so we map update promises
    const updates = subcategories.map((item: any) =>
      supabase.from('subcategories').update({ order_index: item.order_index }).eq('id', item.id)
    );

    await Promise.all(updates);
    res.json({ success: true });
  });

  app.put("/api/subcategories/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    const { error } = await supabase.from('subcategories').update({ name }).eq('id', id);
    if (error) return res.status(400).json({ error: "Update failed" });
    res.json({ success: true });
  });

  app.delete("/api/subcategories/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('subcategories').delete().eq('id', id);
    if (error) return res.status(400).json({ error: "Delete failed" });
    res.json({ success: true });
  });

  // Products
  app.get("/api/products", async (req, res) => {
    const { category, subcategory, featured, search } = req.query;

    let query = supabase
      .from('products')
      .select('*, categories(name), subcategories(name)')
      .order('created_at', { ascending: false });

    if (category) query = query.eq('category_id', category);
    if (subcategory) query = query.eq('subcategory_id', subcategory);
    if (featured === "true") query = query.eq('featured', 1);

    if (search) {
      query = query.or(`name.ilike.%${search}%,description.ilike.%${search}%,keywords.ilike.%${search}%`);
    }

    const { data: products, error } = await query;
    if (error) {
      console.error("❌ ERRO AO BUSCAR PRODUTOS:", error.message);
      return res.status(500).json({ error: "Failed to fetch products", details: error.message });
    }

    // Format top match SQLite structure "category_name" & "subcategory_name"
    const formatted = products.map((p: any) => ({
      ...p,
      category_name: p.categories?.name,
      subcategory_name: p.subcategories?.name
    }));

    res.json(formatted);
  });

  app.post("/api/products", authenticate, requireAdmin, async (req, res) => {
    const { name, description, image, price, price_original, keywords, link_afiliado, category_id, subcategory_id, featured, tag_label, tag_color } = req.body;

    // Converte IDs vazios ou inválidos de string para null/number
    const catId = category_id && !isNaN(Number(category_id)) ? Number(category_id) : null;
    const subId = subcategory_id && !isNaN(Number(subcategory_id)) ? Number(subcategory_id) : null;

    const { data: result, error } = await supabase
      .from('products')
      .insert([{
        name: name || "Produto Sem Título", 
        description, image, price, price_original, keywords, link_afiliado,
        category_id: catId,
        subcategory_id: subId,
        featured: featured ? 1 : 0, tag_label, tag_color
      }])
      .select()
      .single();

    if (error) {
      console.error("❌ ERRO AO SALVAR PRODUTO:", error.message, error.details);
      return res.status(500).json({ error: "Failed to save product", msg: error.message });
    }
    res.json({ id: result.id });
  });

  app.put("/api/products/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, description, image, price, price_original, keywords, link_afiliado, category_id, subcategory_id, featured, tag_label, tag_color } = req.body;

    const { error } = await supabase
      .from('products')
      .update({ name, description, image, price, price_original, keywords, link_afiliado, category_id, subcategory_id, featured: featured ? 1 : 0, tag_label, tag_color })
      .eq('id', id);

    if (error) return res.status(500).json({ error: "Update failed" });
    res.json({ success: true });
  });

  app.delete("/api/products/:id", authenticate, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('products').delete().eq('id', id);
    if (error) return res.status(500).json({ error: "Delete failed" });
    res.json({ success: true });
  });

  // Web Scraping
  app.post("/api/admin/scrape", authenticate, requireAdmin, async (req, res) => {
    const { url, categories } = req.body;
    try {
      const response = await axios.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'Referer': 'https://www.google.com/',
          'Upgrade-Insecure-Requests': '1',
          'DNT': '1',
          'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
          'sec-ch-ua-mobile': '?0',
          'sec-ch-ua-platform': '"Windows"'
        },
        timeout: 10000
      });
      console.log(`[Scrape] Status: ${response.status} para URL: ${url}`);
      const html = response.data;
      const $ = cheerio.load(html);

      let title = $('meta[property="og:title"]').attr('content') || $('title').text() || '';
      let description = $('meta[property="og:description"]').attr('content') || $('meta[name="description"]').attr('content') || '';
      let image = $('meta[property="og:image"]').attr('content') || '';

      if (url.includes('amazon')) {
        const amzTitle = $('#productTitle').text().trim();
        if (amzTitle) title = amzTitle;

        const amzDesc = $('#feature-bullets').text().trim() || $('#productDescription').text().trim();
        if (amzDesc) description = amzDesc;

        let amzImage = $('#landingImage').attr('src') || $('img[data-a-dynamic-image]').first().attr('src');
        if (!amzImage) {
          const dynamicImageStr = $('#landingImage').attr('data-a-dynamic-image');
          if (dynamicImageStr) {
            try {
              const imagesObj = JSON.parse(dynamicImageStr);
              amzImage = Object.keys(imagesObj)[0];
            } catch (e) { }
          }
        }
        if (amzImage) image = amzImage;
      } else if (url.includes('mercadolivre') || url.includes('mlb')) {
        // Seletores atualizados para ML 2024
        const mlTitle = $('.ui-pdp-title').text().trim() || $('h1.ui-pdp-title').text().trim();
        if (mlTitle) title = mlTitle;
        const mlDesc = $('.ui-pdp-description__content').text().trim() || $('#description-show-more').text().trim();
        if (mlDesc) description = mlDesc;
        const mlImg = $('meta[property="og:image"]').attr('content') || $('.ui-pdp-gallery__figure__image').first().attr('src') || $('img.ui-pdp-image').first().attr('src');
        if (mlImg) image = mlImg;
      }

      let price = 0;
      let price_original = 0;

      const extractPriceFast = (text: string) => {
        if (!text) return 0;
        // Clean non-numeric characters except dots and commas
        let raw = text.replace(/[^\d,\.]/g, '');

        if (!raw) return 0;

        // Pattern: "1.234,56" (Common in Brazil)
        if (raw.includes('.') && raw.includes(',')) {
          const lastDot = raw.lastIndexOf('.');
          const lastComma = raw.lastIndexOf(',');
          if (lastComma > lastDot) {
            // Thousands are dots, decimal is comma
            raw = raw.replace(/\./g, '').replace(',', '.');
          } else {
            // Thousands are commas, decimal is dot
            raw = raw.replace(/,/g, '');
          }
        } 
        // Pattern: "1,234.56" or "1.234" (Single separator)
        else if (raw.includes(',')) {
          // If only comma exists, check if it looks like decimal or thousand
          const parts = raw.split(',');
          const lastPart = parts[parts.length - 1];
          if (lastPart.length <= 2) {
             raw = raw.replace(',', '.'); // Decimals (ex: 15,9 ou 15,90)
          } else {
             raw = raw.replace(',', ''); // Thousands (ex: 1,000)
          }
        } else if (raw.includes('.')) {
          const parts = raw.split('.');
          if (parts[parts.length - 1].length === 3) {
            raw = raw.replace('.', ''); // Thousands (e.g. 1.000)
          }
        }

        const finalVal = parseFloat(raw);
        if (isNaN(finalVal)) return 0;
        
        // Garantir que não perdemos precisão se o número for muito grande
        return Number(finalVal.toFixed(2));
      };

      const cleanTitle = (text: string) => {
        if (!text) return "";
        let cleaned = text;
        // Remove variações de R$, R $, $ etc
        cleaned = cleaned.replace(/(R\$\s?|\$\s?|RS\$\s?)\d+([.,]\d+)?([.,]\d+)?/gi, '');
        // Remove padrões de parcelamento (10x de...)
        cleaned = cleaned.replace(/\d+x\s?de\s?(R\$\s?|\$\s?|RS\$\s?)[\d.,]+/gi, '');
        // Remove preços soltos no final (ex: 1.299,00)
        cleaned = cleaned.replace(/\s+[\d.,]{2,}\s*$/, '');
        // Remove separadores comuns que ficam sobrando
        cleaned = cleaned.replace(/\s*[-|]\s*$/, '');
        cleaned = cleaned.replace(/^\s*[-|]\s*/, '');
        
        return cleaned.trim();
      };

      // Extract price heuristics
      try {
        if (url.includes('amazon')) {
          const priceStr = $('#priceblock_ourprice').text() || $('#priceblock_dealprice').text() || $('.priceToPay .a-offscreen').first().text() || $('.a-price .a-offscreen').first().text() || $('.a-color-price').first().text();
          price = extractPriceFast(priceStr);

          if (price === 0) {
            const whole = $('.a-price-whole').first().text().replace(/[^\d]/g, '');
            const fraction = $('.a-price-fraction').first().text().replace(/[^\d]/g, '');
            if (whole && fraction) {
              price = parseFloat(`${whole}.${fraction}`);
            } else if (whole) {
              price = parseFloat(whole);
            }
          }

          const origPriceStr = $('#listPrice').text() || $('.basisPrice .a-offscreen').first().text() || $('.a-text-price .a-offscreen').first().text();
          price_original = extractPriceFast(origPriceStr);


        } else if (url.includes('mercadolivre') || url.includes('mlb')) {
          const fraction = $('.ui-pdp-price__second-line .andes-money-amount__fraction').first().text();
          const cents = $('.ui-pdp-price__second-line .andes-money-amount__cents').first().text();
          
          if (fraction) {
            price = parseFloat(fraction.replace(/\./g, '') + (cents ? '.' + cents : ''));
          } else {
            const metaPrice = $('meta[itemprop="price"]').attr('content');
            price = metaPrice ? parseFloat(metaPrice) : 0;
          }

          const origFraction = $('.ui-pdp-price__original-value .andes-money-amount__fraction').first().text();
          const origCents = $('.ui-pdp-price__original-value .andes-money-amount__cents').first().text();
          if (origFraction) {
            price_original = parseFloat(origFraction.replace(/\./g, '') + (origCents ? '.' + origCents : ''));
          }

        } else if (url.includes('shopee')) {
          const priceStr = $('.items-center .text-orange-500').text() || $('div[class*="price"]').first().text();
          price = extractPriceFast(priceStr);
        } else if (url.includes('aliexpress')) {
          const priceStr = $('.product-price-value').text() || $('.pdp-info-right .price--currentPriceText--V8_y_b5').text();
          price = extractPriceFast(priceStr);
        }
      } catch (e) {
        console.error("Price parsing error", e);
      }

      // Keyword and Category inference
      let keywords = '';
      let category_id = '';
      let subcategory_id = '';

      const content = (title + " " + description).toLowerCase();

      const synonymMap: Record<string, string[]> = {
        'smartphone': ['celular', 'telefone', 'mobile', 'android', 'ios'],
        'iphone': ['apple', 'smartphone', 'ios', 'celular'],
        'notebook': ['laptop', 'computador portátil', 'pc', 'trabalho'],
        'mouse': ['periférico', 'sem fio', 'gamer', 'acessório'],
        'teclado': ['periférico', 'mecânico', 'acessório', 'gamer'],
        'ps5': ['playstation', 'console', 'videogame', 'sony', 'jogos'],
        'xbox': ['console', 'videogame', 'microsoft', 'jogos'],
        'tênis': ['calçado', 'sapato', 'corrida', 'esporte', 'sneaker'],
        'camisa': ['camiseta', 'roupa', 'vestuário', 'moda'],
        'geladeira': ['eletrodoméstico', 'refrigerador', 'cozinha'],
        'televisão': ['tv', 'smart tv', 'tela', '4k', 'filmes'],
        'monitor': ['tela', 'display', 'pc', 'gamer'],
        'fone': ['headset', 'áudio', 'música', 'bluetooth', 'ouvido']
      };

      // EXTRAÇÃO DE PALAVRAS COM SUPORTE TOTAL A ACENTOS (Unicode)
      const stopwords = ['para', 'com', 'mais', 'como', 'mas', 'foi', 'por', 'ele', 'essa', 'isso', 'que', 'dos', 'das', 'uma', 'um', 'modelo', 'cor', 'tamanho', 'sobre', 'este', 'perfeito', 'ideal', 'melhor', 'oferta', 'promoção'];
      
      // Regex /u permite suporte a \p{L} (qualquer letra de qualquer alfabeto) e \p{N} (números)
      const words = title.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length > 2 && !stopwords.includes(w) && !Number.isInteger(Number(w)));

      const generatedKeywords = new Set<string>();
      words.forEach(w => {
        for (const [key, synList] of Object.entries(synonymMap)) {
          if (w === key || w.includes(key) || key.includes(w)) {
            synList.forEach(s => generatedKeywords.add(s));
          }
        }
      });

      // Adiciona o próprio título picado como keywords básicas
      words.slice(0, 8).forEach(w => generatedKeywords.add(w));
      
      keywords = Array.from(generatedKeywords).slice(0, 15).join(', ');

      // Determine category and subcategory based on text
      let aiUsed = false;
      if (process.env.GEMINI_API_KEY) {
        try {
          const ai = new (GoogleGenAI as any)(process.env.GEMINI_API_KEY);
          const model = ai.getGenerativeModel({ model: "gemini-1.5-flash" });
          
          const prompt = `Analise este produto para nosso marketplace de achadinhos:
Título: ${title}
Descrição: ${description.substring(0, 500)}

Categorias e Subcategorias DISPONÍVEIS:
${categories ? categories.map((c: any) => `- Categoria: "${c.name}" (ID: ${c.id}) | Subcategorias: [${c.subcategories?.map((s: any) => `"${s.name}" (ID: ${s.id})`).join(', ')}]`).join('\n') : 'Nenhuma'}

REGRAS CRÍTICAS:
1. Retorne APENAS o JSON puro. Proibido usar marcações de código como blocos de JSON.
2. "keywords": Liste de 6 a 10 palavras que NÃO estão no título.
3. "category_id": USE O ID NUMÉRICO das opções enviadas.
4. "subcategory_id": USE O ID NUMÉRICO das opções enviadas.

Dica: Se o produto for de cozinha, pratos, talheres, copos, potes ou balanças, ele deve ir para o ID de CATEGORIA que tenha nome "CASA" ou similar, e ID de SUBCATEGORIA "COZINHA".`;

          const result = await model.generateContent(prompt);
          const response = await result.response;
          let aiText = response.text();

          if (aiText) {
            aiText = aiText.replace(/```json/gi, '').replace(/```/g, '').trim();
            const aiResult = JSON.parse(aiText);
            
            if (aiResult.keywords) keywords = aiResult.keywords;
            
            // Lógica robusta para categorias (aceita nome ou ID e faz match parcial)
            if (aiResult.category_id && categories) {
               const catIdStr = aiResult.category_id.toString().toLowerCase();
               const category = categories.find((c: any) => 
                  c.id.toString() === catIdStr || 
                  c.name.toLowerCase() === catIdStr ||
                  c.name.toLowerCase().includes(catIdStr)
               );

               if (category) {
                  category_id = category.id.toString();
                  if (aiResult.subcategory_id) {
                     const subIdStr = aiResult.subcategory_id.toString().toLowerCase();
                     const sub = category.subcategories?.find((s: any) => 
                        s.id.toString() === subIdStr || 
                        s.name.toLowerCase() === subIdStr ||
                        s.name.toLowerCase().includes(subIdStr) ||
                        subIdStr.includes(s.name.toLowerCase())
                     );
                     if (sub) subcategory_id = sub.id.toString();
                  }
               }
            }
            
            console.log("🔥 AI (GEMINI) SUCCESS:", aiText);
            aiUsed = true;
          }
        } catch (e) {
          console.error("Gemini AI failed, using fallback:", e);
        }
      }

      // HEURÍSTICA MANUAL DE ELITE (Robusta para Achadinhos)
      if (!aiUsed && categories && Array.isArray(categories)) {
        const contentLower = content.toLowerCase();

        // 🏠 CASA & COZINHA (Foco em Potes, Talheres, Copos, Balanças)
        if (contentLower.includes('casa') || contentLower.includes('cozinha') || contentLower.includes('pote') || contentLower.includes('talher') || contentLower.includes('inox') || contentLower.includes('térmico') || contentLower.includes('balança') || contentLower.includes('copo') || contentLower.includes('garrafa') || contentLower.includes('panela') || contentLower.includes('gastronomia') || contentLower.includes('móvel') || contentLower.includes('aspirador') || contentLower.includes('decoração') || contentLower.includes('sala')) {
          const casaCat = categories.find((c: any) => c.name.toLowerCase().includes('casa') || c.name.toLowerCase().includes('🏠'));
          if (casaCat) {
            category_id = casaCat.id.toString();
            // Match para Cozinha
            if (contentLower.includes('cozinha') || contentLower.includes('pote') || contentLower.includes('talher') || contentLower.includes('balança') || contentLower.includes('copo') || contentLower.includes('garrafa') || contentLower.includes('mantimento') || contentLower.includes('faqueiro') || contentLower.includes('panela') || contentLower.includes('air fryer') || contentLower.includes('térmico')) {
              subcategory_id = casaCat.subcategories?.find((s: any) => s.name.toLowerCase().includes('cozinha'))?.id?.toString() || "";
            }
          }
        }
        
        // 💻 TECH & GADGETS
        else if (contentLower.includes('gamer') || contentLower.includes('pc') || contentLower.includes('computador') || contentLower.includes('notebook') || contentLower.includes('smartphone') || contentLower.includes('celular') || contentLower.includes('fone') || contentLower.includes('watch') || contentLower.includes('eletrônico')) {
          const techCat = categories.find((c: any) => c.name.toLowerCase().includes('tech') || c.name.toLowerCase().includes('eletrônicos') || c.name.toLowerCase().includes('💻'));
          if (techCat) {
            category_id = techCat.id.toString();
            if (contentLower.includes('mouse') || contentLower.includes('teclado') || contentLower.includes('microfone') || contentLower.includes('headset')) subcategory_id = techCat.subcategories?.find((s: any) => s.name.toLowerCase().includes('periférico'))?.id?.toString() || "";
            else if (contentLower.includes('placa') || contentLower.includes('cooler') || contentLower.includes('ssd')) subcategory_id = techCat.subcategories?.find((s: any) => s.name.toLowerCase().includes('hardware'))?.id?.toString() || "";
            else if (contentLower.includes('ps5') || contentLower.includes('xbox') || contentLower.includes('game') || contentLower.includes('jogo')) subcategory_id = techCat.subcategories?.find((s: any) => s.name.toLowerCase().includes('game'))?.id?.toString() || "";
          }
        }

        // 👕 MODA
        else if (contentLower.includes('roupa') || contentLower.includes('camisa') || contentLower.includes('vestido') || contentLower.includes('calça') || contentLower.includes('tênis') || contentLower.includes('calçado') || contentLower.includes('acessório')) {
          const modaCat = categories.find((c: any) => c.name.toLowerCase().includes('moda') || c.name.toLowerCase().includes('👕'));
          if (modaCat) {
            category_id = modaCat.id.toString();
            if (contentLower.includes('tênis') || contentLower.includes('sapato')) subcategory_id = modaCat.subcategories?.find((s: any) => s.name.toLowerCase().includes('tênis') || s.name.toLowerCase().includes('sapato'))?.id?.toString() || "";
          }
        }
      }

      console.log(`[Categorização Final] Produto: ${title.substring(0, 30)}... -> Cat: ${category_id || 'N/A'}, Sub: ${subcategory_id || 'N/A'}`);

        // Fallback basic exact matching (if subcat matches)
        if (!category_id) {
          for (const cat of categories) {
            if (content.includes(cat.name.toLowerCase())) {
              category_id = cat.id.toString();
              break;
            }
          }
        }

      res.json({
        name: cleanTitle(title).substring(0, 100),
        description: description.trim().substring(0, 500),
        image,
        price,
        price_original,
        keywords,
        category_id,
        subcategory_id
      });
    } catch (e) {
      console.error("Scrape error:", e);
      res.status(500).json({ error: "Falha ao extrair dados do link. Verifique a URL ou edite manualmente." });
    }
  });

  // Click Tracking
  app.post("/api/products/:id/click", async (req, res) => {
    const { id } = req.params;

    // Increment clicks using rpc or two queries
    // Usually Supabase recommends RPC for increment: `CREATE OR REPLACE FUNCTION increment_click(row_id bigint) RETURNS void...`
    // Alternatively, fetch and update:
    const { data } = await supabase.from('products').select('clicks').eq('id', id).single();
    if (data) {
      await supabase.from('products').update({ clicks: (data.clicks || 0) + 1 }).eq('id', id);
    }

    await supabase.from('clicks_log').insert([{ product_id: id }]);

    res.json({ success: true });
  });

  // Stats
  // Since complex aggregations with dynamic WHEREs are hard with pure PostgREST (Supabase Client),
  // we will fetch necessary data and aggregate in JS for simplicity, or use simple counts.
  app.get("/api/stats", authenticate, async (req, res) => {
    const { start, end, category_id, subcategory_id } = req.query;

    // 1. Total Products Count
    let productsQuery = supabase.from('products').select('id', { count: 'exact', head: true });
    if (category_id) productsQuery = productsQuery.eq('category_id', category_id);
    if (subcategory_id) productsQuery = productsQuery.eq('subcategory_id', subcategory_id);
    const { count: totalProducts } = await productsQuery;

    // 2. Fetch Clicks Log for total clicks and top products aggregation
    let clicksQuery = supabase
      .from('clicks_log')
      .select('product_id, products!inner(id, name, category_id, subcategory_id)');

    if (start) clicksQuery = clicksQuery.gte('created_at', start);
    if (end) clicksQuery = clicksQuery.lte('created_at', end);
    if (category_id) clicksQuery = clicksQuery.eq('products.category_id', category_id);
    if (subcategory_id) clicksQuery = clicksQuery.eq('products.subcategory_id', subcategory_id);

    const { data: clicksData, error: clicksError } = await clicksQuery;

    if (clicksError) return res.status(500).json({ error: "Failed to load stats" });

    const totalClicks = clicksData.length;

    // Aggregate Top Products in memory
    const productCounts: Record<string, { name: string, clicks: number }> = {};

    clicksData.forEach((click: any) => {
      const pid = click.product_id;
      if (!productCounts[pid]) {
        productCounts[pid] = { name: click.products.name, clicks: 0 };
      }
      productCounts[pid].clicks++;
    });

    const topProducts = Object.values(productCounts)
      .sort((a, b) => b.clicks - a.clicks)
      .slice(0, 5);

    res.json({
      totalProducts: totalProducts || 0,
      totalClicks: totalClicks,
      topProducts
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  const PORT = parseInt(process.env.PORT || "3000", 10);
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

// Script de migração para detectar lojas em produtos antigos
const migrateProductStores = async () => {
  try {
    const { data: products, error } = await supabase.from('products').select('id, link_afiliado');
    if (error) {
      console.error("Erro ao buscar produtos para migração:", error);
      return;
    }
    const getStoreFromUrl = (url: string) => {
      if (!url) return 'Principal';
      const lower = url.toLowerCase();
      // Amazon
      if (lower.includes('amazon') || lower.includes('amzn.')) return 'Amazon';
      // Mercado Livre
      if (lower.includes('mercadolivre') || lower.includes('mercadolibre') || lower.includes('mlb-') || lower.includes('mlb')) return 'Mercado Livre';
      // Outros
      if (lower.includes('shopee')) return 'Shopee';
      if (lower.includes('magazineluiza') || lower.includes('magalu')) return 'Magalu';
      if (lower.includes('aliexpress') || lower.includes('ali.')) return 'AliExpress';
      if (lower.includes('casasbahia')) return 'Casas Bahia';
      return 'Mercado Livre';
    };

    for (const p of products) {
      let links = [];
      let updated = false;
      try {
        const parsed = JSON.parse(p.link_afiliado);
        if (Array.isArray(parsed)) {
          links = parsed.map(l => {
            const currentStore = (l.store || 'Principal').toString().toLowerCase().trim();
            if (currentStore === 'principal' || currentStore === 'oferta' || currentStore === 'ver oferta' || currentStore === 'ofertas') {
              const detected = getStoreFromUrl(l.url);
              l.store = detected; 
              updated = true;
            }
            return l;
          });
        } else {
          const detected = getStoreFromUrl(p.link_afiliado);
          links = [{ store: detected, url: p.link_afiliado }];
          updated = true;
        }
      } catch (e) {
        const detected = getStoreFromUrl(p.link_afiliado);
        links = [{ store: detected, url: p.link_afiliado }];
        updated = true;
      }

      if (updated) {
        console.log(`[MIGRAÇÃO] Atualizando produto ${p.id} -> ${JSON.stringify(links)}`);
        await supabase.from('products').update({ link_afiliado: JSON.stringify(links) }).eq('id', p.id);
      }
    }
    console.log("[MIGRAÇÃO] Concluída.");
  } catch (err) {
    console.error("Falha na migração:", err);
  }
};

startServer().then(() => {
  migrateProductStores();
});
