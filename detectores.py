# -*- coding: utf-8 -*-
"""
Detectores del auditor:

  1. detectar_tecnologias()   -> fingerprinting por firmas (Wappalyzer-lite)
  2. extraer_contactos()      -> emails, teléfonos y redes sociales
  3. detectar_exposicion()    -> detección DEFENSIVA de datos sensibles expuestos
                                 (los valores se reportan SIEMPRE enmascarados)
  4. analizar_seguridad_http()-> cabeceras de seguridad del sitio
"""

import re

from firmas_tecnologia import FIRMAS, CATEGORIAS

# ======================================================================
# 1. TECNOLOGÍAS
# ======================================================================

def detectar_tecnologias(html, scripts, meta_generador, cabeceras, cookies):
    """
    Aplica todas las firmas sobre las evidencias recolectadas del sitio.

    Parámetros:
      html           : HTML concatenado de todas las páginas visitadas.
      scripts        : lista de URLs de recursos (script/img/link externos).
      meta_generador : lista con los valores de <meta name="generator">.
      cabeceras      : dict de cabeceras HTTP (nombre en minúsculas -> valor).
      cookies        : lista de nombres de cookies observadas.

    Devuelve: dict {categoria: [tecnologías detectadas]} (solo categorías con hallazgos).
    """
    html = html or ""
    scripts_txt = "\n".join(scripts or [])
    gen_txt = "\n".join(meta_generador or [])
    cookies_txt = ";".join(cookies or [])
    cabeceras = {str(k).lower(): str(v) for k, v in (cabeceras or {}).items()}
    cabeceras_txt = "\n".join(f"{k}: {v}" for k, v in cabeceras.items())

    resultado = {c: [] for c in CATEGORIAS}

    for firma in FIRMAS:
        if _firma_detectada(firma, html, scripts_txt, gen_txt, cabeceras, cabeceras_txt, cookies_txt):
            resultado[firma["categoria"]].append(firma["nombre"])

    return {cat: sorted(set(techs)) for cat, techs in resultado.items() if techs}


def _firma_detectada(firma, html, scripts_txt, gen_txt, cabeceras, cabeceras_txt, cookies_txt):
    for patron in firma.get("html", []):
        if re.search(patron, html, re.IGNORECASE):
            return True
    for patron in firma.get("scripts", []):
        if re.search(patron, scripts_txt, re.IGNORECASE):
            return True
    for patron in firma.get("meta_generador", []):
        if re.search(patron, gen_txt, re.IGNORECASE):
            return True
    for patron in firma.get("cookies", []):
        if re.search(patron, cookies_txt):
            return True
    for patron in firma.get("cabeceras_cualquiera", []):
        if re.search(patron, cabeceras_txt, re.IGNORECASE):
            return True
    for nombre, patron in firma.get("cabeceras", []):
        if nombre in cabeceras and re.search(patron, cabeceras[nombre], re.IGNORECASE):
            return True
    return False


# ======================================================================
# 2. CONTACTOS (emails, teléfonos, redes sociales)
# ======================================================================

RE_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b")
# Variante ofuscada: nombre [at] dominio [dot] com
RE_EMAIL_OFUSCADO = re.compile(
    r"(?i)\b([a-z0-9._%+\-]{1,40})\s*(?:\[at\]|\(at\)|\sat\s|&#64;|arroba)\s*"
    r"([a-z0-9\-]{1,40}(?:\s*(?:\[dot\]|\(dot\)|\.)\s*[a-z0-9\-]{1,20}){1,3})\s*(?:\[dot\]|\(dot\)|\.)\s*([a-z]{2,10})\b")

# TLDs de archivos que generan falsos positivos (usuario@2x.png, etc.)
_TLD_FALSO_POSITIVO = {"png", "jpg", "jpeg", "gif", "webp", "svg", "css", "js",
                       "ico", "woff", "woff2", "ttf", "eot", "avif", "mp4"}
_DOMINIOS_PLACEHOLDER = {"example.com", "ejemplo.com", "domain.com", "tudominio.com",
                         "yourdomain.com", "email.com", "sentry.io", "wixpress.com",
                         "example.org", "test.com", "2x.png"}

# ---- Teléfonos -------------------------------------------------------
# Internacional: +52 55 1234 5678, +1 (415) 555-2671, 0034 91 123 45 67
# (el lookbehind evita coincidencias incrustadas en secuencias más largas,
#  p. ej. dentro de una CLABE)
RE_TEL_INTL = re.compile(
    r"(?<![\d+])(?:\+|00)\d{1,3}[\s().\-]*(?:\(?\d{1,4}\)?[\s.\-]*){1,4}\d{2,4}[\s.\-]*\d{2,4}")
# Local 10-11 dígitos con formato (55) 1234-5678 / 555-123-4567
RE_TEL_LOCAL = re.compile(
    r"(?<![\d+])(?:\(\d{2,4}\)|\d{2,4})[\s.\-]\s*\d{3,4}[\s.\-]\s*\d{4}(?!\d)")

_KW_TELEFONO = ("tel", "teléfono", "telefono", "phone", "cel", "móvil", "movil",
                "whats", "llama", "llámanos", "llamanos", "contacto", "contact",
                "atención", "atencion", "ventas", "soporte", "cdmx", "oficina")

# ---- Redes sociales --------------------------------------------------
DOMINIOS_SOCIALES = {
    "Facebook":   (r"(?:www\.)?facebook\.com/", r"/(sharer|login|tr\?)/"),
    "Instagram":  (r"(?:www\.)?instagram\.com/", r"/(accounts|p/[a-zA-Z0-9_]+$)"),
    "X / Twitter": (r"(?:www\.)?(?:twitter|x)\.com/", r"/(intent|share|search\?|hashtag)/"),
    "LinkedIn":   (r"(?:www\.)?linkedin\.com/(?:company|in|school|showcase)/", None),
    "YouTube":    (r"(?:www\.)?youtube\.com/(?:@|channel/|c/|user/)", r"/(watch|embed|shorts)/"),
    "TikTok":     (r"(?:www\.)?tiktok\.com/@", None),
    "WhatsApp":   (r"(?:wa\.me/|api\.whatsapp\.com/send|chat\.whatsapp\.com/)", None),
    "Telegram":   (r"t\.me/", None),
    "Pinterest":  (r"(?:www\.)?pinterest\.[a-z.]+/", r"/pin/"),
    "GitHub":     (r"(?:www\.)?github\.com/", r"/(issues|pull|blob|search)/"),
    "Threads":    (r"(?:www\.)?threads\.net/@", None),
    "Snapchat":   (r"(?:www\.)?snapchat\.com/add/", None),
    "Vimeo":      (r"vimeo\.com/\d*[a-z]", r"/\d+$"),
    "Discord":    (r"discord\.(?:gg|com/invite)/", None),
    "Mercado Libre": (r"(?:www\.)?mercadolibre\.[a-z.]+/(?:tiendas|perfil)/", None),
}


def _limpiar_email(email):
    email = email.strip().strip(".,;:()[]<>").lower()
    return email or None


def extraer_emails(texto, mailtos):
    """Emails del texto visible + enlaces mailto:, con filtros anti falso-positivo."""
    hallazgos = set()

    for m in RE_EMAIL.finditer(texto or ""):
        e = _limpiar_email(m.group(0))
        if not e:
            continue
        dominio = e.split("@", 1)[1]
        tld = dominio.rsplit(".", 1)[-1]
        if tld in _TLD_FALSO_POSITIVO:
            continue
        if any(d in dominio for d in _DOMINIOS_PLACEHOLDER):
            continue
        hallazgos.add(e)

    for m in mailtos or []:
        correo = m.split(":", 1)[1].split("?")[0] if ":" in m else m
        e = _limpiar_email(correo)
        if e and "@" in e:
            hallazgos.add(e)

    for m in RE_EMAIL_OFUSCADO.finditer(texto or ""):
        local = m.group(1).strip()
        medio = re.sub(r"\s*(\[dot\]|\(dot\))\s*", ".", m.group(2), flags=re.IGNORECASE)
        tld = m.group(3).strip()
        e = _limpiar_email(f"{local}@{medio}.{tld}")
        if e:
            hallazgos.add(e)

    return sorted(hallazgos)


def _contexto(texto, inicio, fin, radio=120):
    return texto[max(0, inicio - radio):fin + radio].lower()


def extraer_telefonos(texto, tel_links):
    """
    Teléfonos desde enlaces tel: y desde el texto visible.
    Devuelve lista de dicts {"numero", "tipo", "confianza"}.
    """
    hallazgos = {}

    for enlace in tel_links or []:
        num = enlace.split(":", 1)[1] if ":" in enlace else enlace
        num = num.split("?")[0].strip()
        digitos = re.sub(r"\D", "", num)
        if 7 <= len(digitos) <= 15:
            hallazgos.setdefault(digitos, {"numero": num, "tipo": "enlace tel:", "confianza": "alta"})

    for m in RE_TEL_INTL.finditer(texto or ""):
        crudo = m.group(0).strip()
        digitos = re.sub(r"\D", "", crudo)
        if 9 <= len(digitos) <= 15:
            hallazgos.setdefault(
                digitos, {"numero": crudo, "tipo": "formato internacional", "confianza": "alta"})

    for m in RE_TEL_LOCAL.finditer(texto or ""):
        crudo = m.group(0).strip()
        digitos = re.sub(r"\D", "", crudo)
        if not (10 <= len(digitos) <= 12):
            continue
        ctx = _contexto(texto, m.start(), m.end())
        if any(kw in ctx for kw in _KW_TELEFONO):
            hallazgos.setdefault(
                digitos, {"numero": crudo, "tipo": "formato local", "confianza": "media"})

    # quitar duplicados: si un número "media" es el final de uno "alta", se descarta
    digitos_alta = [d for d, h in hallazgos.items() if h["confianza"] == "alta"]
    resultado = [
        h for d, h in hallazgos.items()
        if not (h["confianza"] == "media" and any(a.endswith(d) for a in digitos_alta))
    ]
    return resultado


def extraer_redes_sociales(enlaces):
    """Identifica enlaces a redes sociales. Devuelve {red: set(urls)}."""
    redes = {}
    for enlace in enlaces or []:
        enlace_l = enlace.lower()
        if not enlace_l.startswith(("http://", "https://", "//")):
            # wa.me / api.whatsapp.com pueden venir sin esquema en href relativos raros
            if not any(x in enlace_l for x in ("wa.me", "whatsapp", "t.me")):
                continue
        for red, (patron, excluir) in DOMINIOS_SOCIALES.items():
            if re.search(patron, enlace_l):
                if excluir and re.search(excluir, enlace_l):
                    break
                limpio = enlace.split("?")[0].rstrip("/")
                redes.setdefault(red, set()).add(limpio)
                break
    return {red: sorted(urls) for red, urls in sorted(redes.items())}


# ======================================================================
# 3. EXPOSICIÓN DE DATOS SENSIBLES (detección defensiva tipo DLP)
#    ¡IMPORTANTE! Los hallazgos se reportan siempre ENMASCARADOS.
# ======================================================================

def _enmascarar(valor, visibles_ini=4, visibles_fin=2):
    v = re.sub(r"\s", "", str(valor))
    if len(v) <= visibles_ini + visibles_fin:
        return "*" * len(v)
    return v[:visibles_ini] + "*" * (len(v) - visibles_ini - visibles_fin) + v[-visibles_fin:]


def _luhn_valido(digitos):
    if not digitos.isdigit():
        return False
    suma, doble = 0, False
    for ch in reversed(digitos):
        d = int(ch)
        if doble:
            d *= 2
            if d > 9:
                d -= 9
        suma += d
        doble = not doble
    return suma % 10 == 0


# IBAN con tabla de longitudes por país (muestra representativa)
_LONGITUD_IBAN = {"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
                  "BG": 22, "BH": 22, "BR": 29, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
                  "DE": 22, "DK": 18, "DO": 28, "EE": 20, "ES": 24, "FI": 18, "FO": 18,
                  "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
                  "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30,
                  "KW": 30, "KZ": 20, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
                  "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30,
                  "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
                  "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
                  "TN": 24, "TR": 26, "UA": 29, "VG": 24, "XK": 20}

RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
RE_CLABE = re.compile(r"(?<!\d)\d{18}(?!\d)")
RE_TARJETA = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
RE_SWIFT = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

_KW_BANCARIO = ("clabe", "spei", "transferencia", "depósito", "deposito", "cuenta",
                "bancaria", "bancario", "banco", "bank", "iban", "swift", "wire transfer",
                "número de cuenta", "numero de cuenta", "cuenta de banco", "interbancaria")

PATRONES_CLAVES = [
    ("Clave secreta de Stripe (sk_live)", r"sk_live_[0-9A-Za-z]{12,}", "crítica"),
    ("Clave pública de Stripe (pk_live)", r"pk_live_[0-9A-Za-z]{12,}", "baja"),
    ("Clave de AWS (Access Key ID)", r"\bAKIA[0-9A-Z]{16}\b", "crítica"),
    ("Clave de API de Google", r"\bAIza[0-9A-Za-z_\-]{35}\b", "alta"),
    ("Token de GitHub (PAT)", r"\bghp_[0-9A-Za-z]{36,}\b", "alta"),
    ("Token de Slack", r"\bxox[bapors]-[0-9A-Za-z\-]{10,}\b", "alta"),
    ("Token JWT expuesto", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-\.]{10,}\.[A-Za-z0-9_\-]{4,}\b", "media"),
    ("Llave privada en código fuente", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----", "crítica"),
    ("Posible contraseña en texto plano", r"(?i)(?:contraseña|password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"'<>]{5,40}", "media"),
]


def _sanear_contexto(contexto):
    """Enmascara cualquier valor sensible que aparezca en el fragmento de contexto,
    para que el reporte nunca concentre datos sensibles completos."""
    for _tipo, patron, _sev in PATRONES_CLAVES:
        contexto = re.sub(patron, lambda m: _enmascarar(m.group(0)), contexto)
    contexto = RE_IBAN.sub(lambda m: _enmascarar(m.group(0)), contexto)
    contexto = RE_CLABE.sub(lambda m: _enmascarar(m.group(0)), contexto)
    # secuencias de 13+ dígitos (posibles tarjetas/cuentas no tipificadas)
    contexto = re.sub(r"(?<!\d)((?:\d[ \-]?){13,19})(?!\d)",
                      lambda m: _enmascarar(re.sub(r"\D", "", m.group(1))), contexto)
    return contexto


def _registrar(hallazgos, tipo, valor, severidad, url, texto, inicio, nota=""):
    clave = (tipo, _enmascarar(valor))
    if clave in {(h["tipo"], h["valor_enmascarado"]) for h in hallazgos}:
        return
    contexto = texto[max(0, inicio - 90):inicio + 120]
    contexto = re.sub(r"\s+", " ", contexto).strip()
    contexto = _sanear_contexto(contexto)
    hallazgos.append({
        "tipo": tipo,
        "valor_enmascarado": _enmascarar(valor),
        "severidad": severidad,
        "pagina": url,
        "nota": nota,
        "contexto": contexto[:220],
    })


def detectar_exposicion(texto_visible, html, url):
    """
    Busca patrones de datos sensibles potencialmente expuestos públicamente.
    Enfoque DLP: el objetivo es demostrar que el dato está expuesto y debe
    corregirse; los valores se enmascaran en el reporte.
    """
    hallazgos = []
    texto = texto_visible or ""
    fuente = (html or "") + "\n" + texto  # claves API suelen vivir en el HTML/JS

    # --- IBAN ---
    for m in RE_IBAN.finditer(texto):
        crudo = m.group(0)
        compacto = crudo.replace(" ", "")
        pais = compacto[:2]
        if pais in _LONGITUD_IBAN and len(compacto) == _LONGITUD_IBAN[pais]:
            _registrar(hallazgos, f"IBAN expuesto ({pais})", compacto, "alta", url, texto, m.start())

    # --- CLABE interbancaria (México, 18 dígitos) ---
    clabes_reportadas = set()
    for m in RE_CLABE.finditer(texto):
        ctx = _contexto(texto, m.start(), m.end())
        if any(kw in ctx for kw in _KW_BANCARIO):
            clabes_reportadas.add(m.group(0))
            _registrar(hallazgos, "CLABE interbancaria expuesta (18 dígitos)",
                       m.group(0), "alta", url, texto, m.start())

    # --- Números de tarjeta (validación Luhn) ---
    for m in RE_TARJETA.finditer(texto):
        digitos = re.sub(r"\D", "", m.group(0))
        if not (13 <= len(digitos) <= 19) or not _luhn_valido(digitos):
            continue
        # si es la misma secuencia que una CLABE ya reportada, no duplicar
        if any(digitos in c or c in digitos for c in clabes_reportadas):
            continue
        _registrar(hallazgos, "Número de tarjeta con formato válido (Luhn)",
                   digitos, "crítica", url, texto, m.start())

    # --- SWIFT / BIC (con contexto bancario) ---
    for m in RE_SWIFT.finditer(texto):
        ctx = _contexto(texto, m.start(), m.end())
        if any(kw in ctx for kw in ("swift", "bic")) and not ctx.count("swifty"):
            _registrar(hallazgos, "Código SWIFT/BIC expuesto", m.group(0),
                       "media", url, texto, m.start())

    # --- Claves API y secretos (en HTML/JS y texto) ---
    for tipo, patron, severidad in PATRONES_CLAVES:
        for m in re.finditer(patron, fuente):
            nota = ""
            if tipo.startswith("Clave pública de Stripe"):
                nota = ("pk_live es pública por diseño; se reporta para confirmar "
                        "que el sitio usa Stripe. Revisar que NO exista sk_live.")
            _registrar(hallazgos, tipo, m.group(0), severidad, url, fuente, m.start(), nota)

    return hallazgos


# ======================================================================
# 4. CABECERAS DE SEGURIDAD HTTP
# ======================================================================

CABECERAS_SEGURIDAD = {
    "strict-transport-security": ("HSTS", "Fuerza HTTPS en el navegador"),
    "content-security-policy":   ("CSP", "Mitiga XSS e inyección de contenido"),
    "x-frame-options":           ("X-Frame-Options", "Protege contra clickjacking"),
    "x-content-type-options":    ("X-Content-Type-Options", "Evita MIME-sniffing"),
    "referrer-policy":           ("Referrer-Policy", "Controla la info enviada en Referer"),
    "permissions-policy":        ("Permissions-Policy", "Restringe APIs del navegador"),
    "x-xss-protection":          ("X-XSS-Protection", "Filtro XSS heredado"),
}


def analizar_seguridad_http(cabeceras):
    cab = {str(k).lower(): str(v) for k, v in (cabeceras or {}).items()}
    presentes, ausentes = {}, []
    for nombre, (alias, desc) in CABECERAS_SEGURIDAD.items():
        if nombre in cab:
            presentes[alias] = {"valor": cab[nombre][:200], "descripcion": desc}
        else:
            ausentes.append(alias)

    total = len(CABECERAS_SEGURIDAD)
    score = round(100 * len(presentes) / total)
    return {
        "presentes": presentes,
        "ausentes": ausentes,
        "puntuacion": f"{len(presentes)}/{total} ({score}%)",
        "https": cab.get("_esquema_https", "desconocido"),
    }
