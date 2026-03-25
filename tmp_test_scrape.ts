import axios from "axios";
import * as cheerio from "cheerio";

async function testAmz() {
    try {
        const res = await axios.get("https://www.amazon.com.br/Kindle-11a-geracao-preto/dp/B09SWTG9GF", {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
                'Accept-Language': 'pt-BR,pt;q=0.9',
                'Accept': 'text/html'
            }
        });
        const $ = cheerio.load(res.data);
        let amzPrice = $('.priceToPay .a-offscreen').first().text() || $('.a-price .a-offscreen').first().text() || $('.a-color-price').first().text();
        let amzOrig = $('.basisPrice .a-offscreen').first().text() || $('.a-text-price .a-offscreen').first().text();

        // Sometimes amazon uses different classes for prices
        if (!amzPrice) {
            const whole = $('.a-price-whole').first().text();
            const fraction = $('.a-price-fraction').first().text();
            if (whole) amzPrice = whole + (fraction ? ',' + fraction : '');
        }

        let image = $('#landingImage').attr('src') || $('img[data-a-dynamic-image]').first().attr('src') || $('meta[property="og:image"]').attr('content');
        if (!image) {
            const dynamicImageStr = $('#landingImage').attr('data-a-dynamic-image');
            if (dynamicImageStr) {
                try {
                    const images = JSON.parse(dynamicImageStr);
                    image = Object.keys(images)[0];
                } catch (e) { }
            }
        }

        console.log("AMZ price:", amzPrice);
        console.log("AMZ orig:", amzOrig);
        console.log("AMZ image:", image);
    } catch (e) { console.log("AMZ err", e.message); }
}

testAmz();
