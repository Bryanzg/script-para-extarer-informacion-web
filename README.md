# 🔎 Script para extraer información web

Auditor automatizado que extrae la **información pública** de los sitios web de una lista
de empresas: stack tecnológico completo, datos de contacto publicados y detección
defensiva (tipo DLP) de **datos sensibles expuestos** públicamente.

```
┌─ Stack tecnológico ──────────────┐
│ CMS · Ecommerce · Analytics      │
│ Advertising · Payments · Chat    │
│ Marketing · Reviews · Consent    │
│ Experimentation · Search         │
│ Scheduling · Frameworks          │
│ CDN/hosting · Server             │
│ Seguridad/monitoreo · Media/mapas│
└──────────────────────────────────┘
┌─ Contacto ───────────────────────┐
│ ✉️ Emails (texto, mailto:,       │
│    ofuscados [at][dot])          │
│ 📞 Teléfonos (tel:, intl, local) │
│ 🔗 Redes sociales (14 plataformas)│
└──────────────────────────────────┘
┌─ Exposición de datos (DLP) ──────┐
│ IBAN · CLABE · SWIFT/BIC         │
│ Tarjetas (validación Luhn)       │
│ Claves API (Stripe, AWS, Google, │
│ GitHub, Slack) · JWT · llaves    │
│ privadas · contraseñas visibles  │
│     ↳ SIEMPRE ENMASCARADOS (•••) │
└──────────────────────────────────┘
┌─ Seguridad HTTP ─────────────────┐
│ HSTS · CSP · X-Frame-Options ·   │
│ X-Content-Type-Options ·         │
│ Referrer-Policy · Permissions... │
└──────────────────────────────────┘
```

---

## ⚖️ Uso responsable (léase antes de ejecutar)

- Ejecuta esta herramienta **únicamente sobre sitios propios o con autorización escrita**
  para auditarlos. El acceso no autorizado a sistemas informáticos es delito en la
  mayoría de jurisdicciones.
- El script **solo lee páginas públicas**: no intenta autenticarse, no evade captchas,
  no explota vulnerabilidades ni hace fuerza bruta.
- La detección de datos sensibles es **defensiva**: sirve para *demostrar que un sitio
  expone datos y debe corregirlo*. Los valores se reportan **enmascarados**
  (`0121************65`) tanto en el hallazgo como en el contexto, para que el reporte
  no se convierta en un concentrado de datos sensibles.
- `robots.txt` se **respeta por defecto** (`--ignorar-robots` solo para sitios propios).
- La recolección de emails/teléfonos publicados puede estar sujeta a GDPR (UE),
  LFPDPPP (México) y leyes anti-spam. Úsalos conforme a la ley.
- Si encuentras una fuga de datos sensibles en un sitio de terceros, lo correcto es
  **notificarlo** a su equipo de seguridad (divulgación responsable).

---

## 🚀 Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Dependencias: `requests` y `beautifulsoup4` (Python ≥ 3.9).

## ▶️ Uso

1. Prepara la lista de empresas en **cualquiera de estos formatos**:

   **a) Texto plano** (`empresas.txt`), una URL por línea:

   ```
   https://www.empresa1.com
   empresa2.mx             # se agrega https:// automáticamente
   # líneas con # son comentarios
   ```

   **b) CSV / TSV** (ej. `empresas_y_sitios_web.csv`). El script detecta
   automáticamente el delimitador (`,` `;` tab `|`), la **columna de URLs**
   (por nombre: `url`, `sitio web`, `website`, `dominio`, … o por contenido)
   y, si existe, la **columna con el nombre de la empresa** (`empresa`,
   `nombre`, `razón social`, `compañía`, …) para etiquetar el reporte:

   ```csv
   Empresa,Sitio web,Sector
   Acme Demo,https://www.empresa1.com,Software
   Distribuidora XYZ,empresa2.mx,Retail
   ```

   No importa si el CSV trae más columnas (sector, dirección, etc.): se
   usan solo la empresa y el sitio web.

2. Ejecuta:

   ```bash
   python extractor.py empresas.txt --salida salida/
   # o directamente el CSV:
   python extractor.py empresas_y_sitios_web.csv --salida salida/
   ```

3. Abre los resultados (ver siguiente sección).

### Prueba sin red

```bash
python extractor.py --auto-test
```

Ejecuta 17 auto-pruebas de los detectores contra un HTML de muestra (no requiere Internet).

### Opciones

| Opción | Defecto | Descripción |
|---|---|---|
| `--salida, -o` | `salida/` | Carpeta de resultados |
| `--max-paginas` | `12` | Páginas internas máx. por sitio (portada + contacto, aviso legal, privacidad, tienda, etc.) |
| `--max-paginas-exposicion` | `12` | Páginas máx. donde buscar datos sensibles |
| `--delay` | `1.0` | Segundos entre peticiones (sé amable con el servidor) |
| `--timeout` | `15` | Timeout por petición HTTP |
| `--ignorar-robots` | off | No respetar robots.txt (solo con autorización) |
| `--inseguro` | off | No verificar certificados TLS |
| `--user-agent` | `WebAuditBot/1.0` | User-Agent identificativo del auditor |

## 📦 Resultados

```
salida/
├── reporte.html              ← reporte visual consolidado (ábrelo en el navegador)
├── resumen.csv               ← tabla consolidada (Excel/Google Sheets)
├── resultado_completo.json   ← JSON con TODO el detalle de todos los sitios
└── <dominio>.json            ← un JSON detallado por cada sitio auditado
```

En [`ejemplos/`](ejemplos/) hay una **salida de demostración real** generada contra un
sitio ficticio ("Acme Demo") con technologies y fugas simuladas:

- [`ejemplos/reporte_demo.html`](ejemplos/reporte_demo.html) — así se ve el reporte
- [`ejemplos/sitio_demo.json`](ejemplos/sitio_demo.json) — estructura del JSON por sitio
- [`ejemplos/resumen_demo.csv`](ejemplos/resumen_demo.csv) — tabla consolidada

### Ejemplo del JSON por sitio

```json
{
  "url_final": "https://www.empresa.com/",
  "tecnologias": {
    "CMS": ["WordPress"],
    "Ecommerce": ["WooCommerce"],
    "Analytics": ["Google Tag Manager"],
    "Payments": ["Stripe", "Mercado Pago"],
    "CDN y hosting": ["Cloudflare"],
    "Server": ["nginx", "PHP"]
  },
  "contacto": {
    "emails": ["contacto@empresa.com"],
    "telefonos": [{"numero": "+52 55 1234 5678", "confianza": "alta"}],
    "redes_sociales": {"Facebook": ["https://facebook.com/empresa"]}
  },
  "exposicion_datos": [{
    "tipo": "CLABE interbancaria expuesta (18 dígitos)",
    "valor_enmascarado": "0121************65",
    "severidad": "alta",
    "pagina": "https://www.empresa.com/contacto",
    "contexto": "...CLABE interbancaria: 0121************65 (solo transferencia SPEI)..."
  }],
  "seguridad_http": {"puntuacion": "2/7 (29%)", "ausentes": ["CSP", "..."]}
}
```

## 🧩 Cobertura del fingerprinting

**~220 firmas** en las 17 categorías solicitadas (+ "Otros"):

| Categoría | Ejemplos detectados |
|---|---|
| CMS | WordPress, Drupal, Joomla, Shopify, Wix, Squarespace, Webflow, Ghost, PrestaShop, Craft, Odoo… |
| Ecommerce | WooCommerce, Shopify, Magento, PrestaShop, VTEX, BigCommerce, TiendaNube, Mercado Shops, OpenCart… |
| Analytics | GA4, Universal Analytics, GTM, Hotjar, Clarity, Matomo, Mixpanel, Amplitude, Segment… |
| Advertising | Meta Pixel, Google Ads, AdSense, DoubleClick, LinkedIn Insight, TikTok, Pinterest, Criteo… |
| Payments | Stripe, PayPal, Mercado Pago, Conekta, Openpay, Adyen, Braintree, Square, Klarna, PayU… |
| Chat y soporte | Intercom, Zendesk, Tawk.to, Drift, LiveChat, Crisp, Tidio, WhatsApp widget… |
| Marketing | HubSpot, Mailchimp, Klaviyo, Brevo, ActiveCampaign, Pardot, Marketo, RD Station… |
| Reviews | Trustpilot, Yotpo, Judge.me, Okendo, Stamped, Bazaarvoice, Reviews.io… |
| Consent | OneTrust, Cookiebot, TrustArc, Iubenda, CookieYes, Didomi, Osano, Usercentrics… |
| Experimentation | Optimizely, VWO, Google Optimize, AB Tasty, Dynamic Yield, Kameleoon… |
| Search | Algolia, Swiftype, Doofinder, Coveo, Searchspring, Klevu… |
| Scheduling | Calendly, Acuity, SimplyBook, Setmore, HubSpot Meetings, Cal.com… |
| Frameworks | React, Next.js, Vue, Nuxt, Angular, jQuery, Bootstrap, Tailwind, Gatsby, Astro… |
| CDN y hosting | Cloudflare, Akamai, Fastly, CloudFront, Vercel, Netlify, Azure, Sucuri, WP Engine… |
| Server | nginx, Apache, IIS, LiteSpeed, PHP, ASP.NET, Express, Django, Laravel, Tomcat… |
| Seguridad y monitoreo | reCAPTCHA, hCaptcha, Turnstile, Sentry, New Relic, Datadog, PerimeterX, Imperva… |
| Media y mapas | Google Maps, Mapbox, Leaflet/OSM, YouTube, Vimeo, Cloudinary, Google Fonts… |

Redes sociales: Facebook, Instagram, X/Twitter, LinkedIn, YouTube, TikTok, WhatsApp,
Telegram, Pinterest, GitHub, Threads, Snapchat, Discord, Vimeo y Mercado Libre.

Las firmas viven en [`firmas_tecnologia.py`](firmas_tecnologia.py) y están pensadas para
editarse fácilmente: agrega una entrada con el nombre, categoría y expresiones regulares.

## 🏗️ Arquitectura

| Archivo | Responsabilidad |
|---|---|
| `extractor.py` | CLI, rastreador (portada + páginas internas prioritarias como /contacto, /aviso-legal, /privacidad, /tienda…), robots.txt, orquestación y salidas (JSON/CSV/HTML). |
| `firmas_tecnologia.py` | Catálogo de ~220 firmas tecnológicas editables. |
| `detectores.py` | Fingerprinting, extracción de emails/teléfonos/redes, detección DLP de datos sensibles (con enmascarado) y análisis de cabeceras de seguridad. |

## ⚠️ Limitaciones conocidas

- **Sitios SPA/JS-intensivos**: el rastreador analiza el HTML servido; contenido que solo
  existe tras ejecutar JavaScript en el navegador puede no verse. Para esos casos se
  puede extender `Rastreador.obtener()` con Playwright/Selenium.
- **Hosting por DNS**: el proveedor de hosting se infiere por cabeceras/IP; si el sitio
  no expone cabeceras reveladoras y no usas añadir consultas DNS, puede no detectarse.
- **Falsos positivos/negativos**: los patrones de teléfonos y datos sensibles buscan un
  equilibrio; los teléfonos "locales" solo se reportan con contexto ("tel", "WhatsApp",
  "contacto"…) y los números de tarjeta pasan validación Luhn para minimizar el ruido.
- El detector de CLABE requiere **contexto bancario** cercano (18 dígitos aislados son
  demasiado ambiguos para reportarlos).

## 📜 Licencia

Uso interno del propietario del repositorio. Ver sección **Uso responsable**.
