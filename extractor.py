#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extractor.py — Auditor de información pública de sitios web.

Extrae, por cada sitio de la lista:
  • Stack tecnológico por categorías (CMS, Ecommerce, Analytics, Advertising,
    Payments, Chat y soporte, Marketing, Reviews, Consent, Experimentation,
    Search, Scheduling, Frameworks, CDN y hosting, Server, Seguridad y
    monitoreo, Media y mapas).
  • Emails, teléfonos y redes sociales publicados.
  • Detección DEFENSIVA (tipo DLP) de datos sensibles expuestos públicamente
    (IBAN, CLABE, tarjetas con Luhn válido, claves API, llaves privadas, etc.).
    Los valores SIEMPRE se reportan enmascarados.
  • Análisis de cabeceras de seguridad HTTP.

USO RESPONSABLE: ejecuta esta herramienta únicamente sobre sitios propios o
con autorización escrita para auditar. Respeta robots.txt (activado por
defecto), los límites de peticiones y la legislación de protección de datos
applicable (GDPR, LFPDPPP, etc.).

Uso:
    python extractor.py empresas.txt --salida salida/ --max-paginas 12
    python extractor.py empresas_y_sitios_web.csv   # CSV: detecta la columna de URLs
    python extractor.py --auto-test          # prueba los detectores sin red

Requisitos: pip install -r requirements.txt
"""

import argparse
import csv
import datetime as _dt
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.robotparser

import requests
from bs4 import BeautifulSoup

from detectores import (analizar_seguridad_http, clasificar_negocio,
                        descubrir_categoria, detectar_exposicion,
                        detectar_tecnologias,
                        etiqueta_categoria, extraer_emails,
                        extraer_redes_sociales, extraer_telefonos,
                        minar_html)

VERSION = "1.3.0"
UA_DEFECTO = "WebAuditBot/1.0 (+auditoria-autorizada; contacto: configurar-con --user-agent)"

# Rutas internas prioritarias: ahí suelen estar contacto, datos legales y pagos
_KW_RUTAS = ("contact", "contacto", "about", "nosotros", "quienes", "legal",
             "aviso", "privacy", "privacidad", "terms", "terminos", "términos",
             "ayuda", "help", "faq", "soporte", "support", "tienda", "shop",
             "store", "pago", "pagos", "payment", "facturacion", "facturación",
             "sucursales", "ubicacion", "ubicación", "cotiza", "ventas")

_TAM_MAX_RESPUESTA = 3 * 1024 * 1024  # 3 MB por página


# ----------------------------------------------------------------------
# Utilidades de red / rastreo
# ----------------------------------------------------------------------

def normalizar_url(url):
    url = url.strip()
    if not url:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


_RE_CELDA_URL = re.compile(
    r"^(?:https?://|www\.)?"
    r"(?:[a-z0-9][a-z0-9.\-]*\.[a-z]{2,24}|localhost|\d{1,3}(?:\.\d{1,3}){3})"
    r"(?::\d{1,5})?(?:/[^\s]*)?$", re.I)

# Nombres típicos de la columna con el sitio web en un CSV de empresas
_COLUMNAS_URL = ("url", "urls", "sitio", "sitio web", "sitio_web", "sitio-web",
                 "website", "web", "web site", "pagina", "página", "pagina web",
                 "página web", "dominio", "domain", "site", "homepage", "enlace",
                 "link", "url sitio", "sitio url")
_COLUMNAS_EMPRESA = ("empresa", "nombre", "compañia", "compania", "company",
                     "razon social", "razón social", "organizacion", "organización",
                     "negocio", "business", "cliente")


def _parece_url(celda):
    return bool(_RE_CELDA_URL.match(celda.strip()))


def cargar_lugares(archivo):
    """
    Carga la lista de sitios a auditar. Admite:
      • .txt  -> una URL por línea (comentarios con #)
      • .csv/.tsv -> detecta automáticamente el delimitador, la columna de URLs
        y (si existe) la columna con el nombre de la empresa.

    Devuelve lista de dicts {"url": ..., "empresa": ... o None}, sin duplicados.
    """
    if not archivo.lower().endswith((".csv", ".tsv")):
        with open(archivo, encoding="utf-8-sig") as f:
            crudas = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        return _deduplicar([{"url": u, "empresa": None}
                            for u in (normalizar_url(x) for x in crudas) if u])

    with open(archivo, encoding="utf-8-sig", newline="") as f:
        muestra = f.read(8192)
        f.seek(0)
        primera = muestra.splitlines()[0] if muestra else ""
        delimitador = max((",", ";", "\t", "|"), key=primera.count)
        filas = [fila for fila in csv.reader(f, delimiter=delimitador) if any(fila)]

    if not filas:
        return []

    # ¿la primera fila es cabecera? (ninguna celda parece URL)
    tiene_cabecera = not any(_parece_url(c) for c in filas[0])
    datos = filas[1:] if tiene_cabecera else filas
    cabecera = [c.strip().lower() for c in filas[0]] if tiene_cabecera else []

    def _idx(nombres, prediccion_default=None):
        for i, nombre in enumerate(cabecera):
            if nombre in nombres:
                return i
        return prediccion_default

    idx_url = _idx(_COLUMNAS_URL)
    idx_emp = _idx(_COLUMNAS_EMPRESA)

    if idx_url is None and datos:  # sin pista por cabecera: columna más "URL-osa"
        n_col = max(len(f) for f in datos)
        mejor, mejor_punt = None, 0.0
        for i in range(n_col):
            vals = [f[i] for f in datos if i < len(f) and f[i].strip()]
            punt = sum(_parece_url(v) for v in vals) / len(vals) if vals else 0
            if punt > mejor_punt:
                mejor, mejor_punt = i, punt
        idx_url = mejor if mejor_punt >= 0.4 else None

    lugares = []
    for fila in datos:
        if idx_url is not None and idx_url < len(fila) and _parece_url(fila[idx_url]):
            celda = fila[idx_url]
        else:  # último recurso: primera celda de la fila que parezca URL
            celda = next((c for c in fila if _parece_url(c)), None)
        if not celda:
            continue
        empresa = None
        if idx_emp is not None and idx_emp < len(fila) and fila[idx_emp].strip():
            empresa = fila[idx_emp].strip()
        lugares.append({"url": normalizar_url(celda), "empresa": empresa})
    return _deduplicar(lugares)


def _deduplicar(lugares):
    vistos, unicos = set(), []
    for l in lugares:
        clave = host_base(l["url"]) + (l.get("empresa") or "")
        if clave not in vistos:
            vistos.add(clave)
            unicos.append(l)
    return unicos


def host_base(url):
    host = urllib.parse.urlparse(url).netloc.lower()
    return host[4:] if host.startswith("www.") else host


def es_enlace_interno(enlace, host):
    if not enlace or enlace.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return False
    p = urllib.parse.urlparse(enlace)
    if not p.netloc:
        return True  # relativo
    base = p.netloc.lower()
    base = base[4:] if base.startswith("www.") else base
    return base == host or base.endswith("." + host)


def puntuar_ruta(url):
    camino = urllib.parse.urlparse(url).path.lower()
    return sum(2 for kw in _KW_RUTAS if kw in camino) + (1 if camino.count("/") <= 2 else 0)


class Rastreador:
    """Descarga la portada y las páginas internas más relevantes de un sitio."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.sesion = requests.Session()
        self.sesion.headers.update({
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-MX,es;q=0.9,en;q=0.8",
        })
        self._robots = {}

    # ---- robots.txt ---------------------------------------------------
    def robots_permite(self, url):
        if self.cfg.ignorar_robots:
            return True
        host = urllib.parse.urlparse(url).netloc
        if host not in self._robots:
            rp = urllib.robotparser.RobotFileParser()
            esquema = urllib.parse.urlparse(url).scheme
            try:  # descargar robots.txt con el MISMO user-agent de la auditoría
                r = self.sesion.get(f"{esquema}://{host}/robots.txt",
                                    timeout=self.cfg.timeout,
                                    verify=not self.cfg.inseguro)
                if r.status_code < 400:
                    rp.parse(r.text.splitlines())
                    rp.modified()  # marca el archivo como leído
                else:
                    rp.allow_all = True  # robots.txt no disponible -> sin reglas
            except requests.RequestException:
                rp.allow_all = True  # no se pudo leer -> sin reglas aplicables
            self._robots[host] = rp
        return self._robots[host].can_fetch(
            self.cfg.user_agent.split("/")[0] or "*", url)

    # ---- descarga -----------------------------------------------------
    @staticmethod
    def _decodificar(crudo, r):
        """Respeta el charset del Content-Type; si no viene explícito, prueba
        UTF-8 y como último recurso la detección automática de requests/chardet.

        Ojo: requests asume ISO-8859-1 para text/* sin charset explícito, así
        que r.encoding NO basta como señal de 'charset real'.
        """
        ctype = r.headers.get("Content-Type", "")
        if "charset=" in ctype.lower() and r.encoding:
            return crudo.decode(r.encoding, errors="replace")
        try:
            return crudo.decode("utf-8")
        except UnicodeDecodeError:
            return crudo.decode(r.apparent_encoding or "utf-8", errors="replace")

    def obtener(self, url):
        try:
            with self.sesion.get(url, timeout=self.cfg.timeout,
                                 allow_redirects=True, stream=True,
                                 verify=not self.cfg.inseguro) as r:
                crudo = b""
                for chunk in r.iter_content(65536):
                    crudo += chunk
                    if len(crudo) > _TAM_MAX_RESPUESTA:
                        break
                ctype = r.headers.get("Content-Type", "")
                return {
                    "url": url,
                    "url_final": str(r.url),
                    "estado": r.status_code,
                    "tipo_contenido": ctype,
                    "html": self._decodificar(crudo, r),
                    "cabeceras": dict(r.headers),
                    "cookies": [c.name for c in r.cookies] + [c.name for c in self.sesion.cookies],
                }
        except requests.RequestException as e:
            return {"url": url, "error": f"{type(e).__name__}: {e}"}

    # ---- sitemap.xml / robots.txt (descubrimiento profundo) ----------
    def obtener_urls_sitemap(self, url_inicial, limite=25):
        """Descubre URLs internas vía 'Sitemap:' de robots.txt y /sitemap.xml.
        Devuelve hasta `limite` URLs (las prioriza el puntuador de rutas)."""
        descubiertas, sitemaps = [], []
        host = host_base(url_inicial)
        esquema = urllib.parse.urlparse(url_inicial).scheme
        origen = f"{esquema}://{urllib.parse.urlparse(url_inicial).netloc}"

        try:
            r = self.sesion.get(f"{origen}/robots.txt", timeout=self.cfg.timeout,
                                verify=not self.cfg.inseguro)
            if r.status_code < 400:
                sitemaps += re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", r.text)
        except requests.RequestException:
            pass
        if not sitemaps:
            sitemaps = [f"{origen}/sitemap.xml"]

        def _locs(texto):
            return re.findall(r"<loc>\s*([^<]+?)\s*</loc>", texto or "")

        for mapa in sitemaps[:3]:
            try:
                r = self.sesion.get(mapa, timeout=self.cfg.timeout,
                                    verify=not self.cfg.inseguro)
                if r.status_code >= 400:
                    continue
                cuerpo = r.text[:700_000]
                if "<sitemapindex" in cuerpo:  # índice de sitemaps: bajar un nivel
                    for hijo in _locs(cuerpo)[:5]:
                        try:
                            rh = self.sesion.get(hijo, timeout=self.cfg.timeout,
                                                 verify=not self.cfg.inseguro)
                            if rh.status_code < 400:
                                descubiertas += _locs(rh.text[:700_000])
                        except requests.RequestException:
                            continue
                else:
                    descubiertas += _locs(cuerpo)
            except requests.RequestException:
                continue
            if descubiertas:
                break

        urls, vistos = [], set()
        for u in descubiertas:
            u = u.strip()
            p = urllib.parse.urlparse(u)
            if p.scheme not in ("http", "https") or not es_enlace_interno(u, host):
                continue
            if re.search(r"\.(png|jpe?g|gif|webp|svg|css|js|pdf|zip|mp4|xml)$",
                         p.path, re.I):
                continue
            if u not in vistos:
                vistos.add(u)
                urls.append(u)
            if len(urls) >= limite:
                break
        return urls

    def rastrear(self, url_inicial):
        """Devuelve lista de páginas descargadas (dicts)."""
        host = host_base(url_inicial)
        por_visitar = {url_inicial}
        por_visitar.update(self.obtener_urls_sitemap(url_inicial))
        visitadas = set()
        finales_visitadas = set()
        paginas = []

        while por_visitar and len(paginas) < self.cfg.max_paginas:
            url = sorted(por_visitar, key=puntuar_ruta, reverse=True)[0]
            por_visitar.discard(url)
            url_limpia = url.split("#")[0]
            # clave canónica: sin fragmento ni barra final (/contacto ≡ /contacto/)
            clave = url_limpia.rstrip("/") or url_limpia
            if clave in visitadas:
                continue
            visitadas.add(clave)

            if not self.robots_permite(url_limpia):
                print(f"      [robots.txt] omitida: {url_limpia}")
                continue

            print(f"      GET {url_limpia}")
            resp = self.obtener(url_limpia)
            if "error" in resp:
                paginas.append(resp)  # conservar el error para el reporte
                continue
            if resp["estado"] >= 400 or "text/html" not in resp.get("tipo_contenido", ""):
                if not paginas:  # guardar aunque sea para reportar el estado
                    paginas.append(resp)
                continue

            # deduplicar por URL final (p. ej. /contacto y /contacto/ son la misma página)
            clave_final = resp["url_final"].split("#")[0].rstrip("/")
            if clave_final in finales_visitadas:
                continue
            finales_visitadas.add(clave_final)

            paginas.append(resp)

            # descubrir más rutas internas
            sopa = BeautifulSoup(resp["html"], "html.parser")
            for a in sopa.find_all("a", href=True):
                destino = urllib.parse.urljoin(resp["url_final"], a["href"]).split("#")[0]
                p = urllib.parse.urlparse(destino)
                if p.scheme not in ("http", "https"):
                    continue
                if not es_enlace_interno(destino, host):
                    continue
                if re.search(r"\.(png|jpe?g|gif|webp|svg|css|js|pdf|zip|mp4)$", p.path, re.I):
                    continue
                if destino not in visitadas:
                    por_visitar.add(destino)

            time.sleep(self.cfg.delay)

        return paginas


# ----------------------------------------------------------------------
# Auditoría por sitio
# ----------------------------------------------------------------------

# namespaces de la REST API de WordPress -> plugin asociado
WP_PLUGINS_NS = {
    "contact-form-7": "Contact Form 7 (REST)", "wc": "WooCommerce (REST API)",
    "yoast": "Yoast SEO (REST)", "elementor": "Elementor (REST)",
    "rankmath": "Rank Math SEO (REST)", "jetpack": "Jetpack (REST)",
    "wpml": "WPML (REST)", "polylang": "Polylang (REST)",
    "tribe": "The Events Calendar (REST)", "givewp": "GiveWP (REST)",
    "lifterlms": "LifterLMS (REST)", "learndash": "LearnDash (REST)",
    "flamingo": "Flamingo (REST)", "redirection": "Redirection (REST)",
}


def sondear_wp_json(sesion, origen, cfg):
    """Sondeo profundo de /wp-json/ en sitios WordPress:
    nombre del sitio, descripción y namespaces (delatan plugins activos)."""
    try:
        r = sesion.get(f"{origen}/wp-json/", timeout=cfg.timeout,
                       verify=not cfg.inseguro)
        if r.status_code >= 400 or "json" not in r.headers.get("Content-Type", "").lower():
            return None
        datos = r.json()
    except (requests.RequestException, ValueError):
        return None
    return {
        "nombre_sitio": datos.get("name"),
        "descripcion": (datos.get("description") or "")[:200],
        "url": datos.get("url"),
        "home": datos.get("home"),
        "timezone": datos.get("timezone_string") or datos.get("gmt_offset"),
        "namespaces": [str(n) for n in datos.get("namespaces", [])][:60],
    }


def auditar_sitio(url, cfg, empresa=None):
    rastreador = Rastreador(cfg)
    inicio = time.time()

    paginas = rastreador.rastrear(url)
    paginas_ok = [p for p in paginas if "error" not in p and p.get("estado", 0) < 400]
    errores = [p for p in paginas if "error" in p]

    resultado = {
        "url_solicitada": url,
        "empresa": empresa,
        "fecha_auditoria": _dt.datetime.now().isoformat(timespec="seconds"),
        "paginas_analizadas": [p.get("url_final", p["url"]) for p in paginas_ok],
        "paginas_con_error": [{"url": p["url"], "error": p["error"]} for p in errores],
        "duracion_segundos": round(time.time() - inicio, 1),
    }

    if not paginas_ok:
        resultado["estado"] = "error: no se pudo descargar ninguna página"
        resultado["tecnologias"] = {}
        resultado["contacto"] = {"emails": [], "telefonos": [], "redes_sociales": {}}
        resultado["exposicion_datos"] = []
        return resultado

    resultado["estado"] = "ok"
    principal = paginas_ok[0]
    resultado["url_final"] = principal["url_final"]
    resultado["codigo_http"] = principal["estado"]

    # ---- agregar evidencias de todas las páginas ----
    html_total, scripts, generadores, cookies = [], set(), [], set()
    texto_visible_total, enlaces, mailtos, tel_links = [], set(), set(), set()
    cabeceras_union = {}

    for pag in paginas_ok:
        html_pag = pag["html"]
        html_total.append(html_pag[:400_000])
        cabeceras_union.update({k.lower(): v for k, v in pag["cabeceras"].items()})
        cookies.update(pag["cookies"])

        sopa = BeautifulSoup(html_pag, "html.parser")
        meta_gen = sopa.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
        if meta_gen and meta_gen.get("content"):
            generadores.append(meta_gen["content"])

        for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")):
            for el in sopa.find_all(tag, attrs={attr: True}):
                scripts.add(urllib.parse.urljoin(pag["url_final"], el[attr]))

        for a in sopa.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith("mailto:"):
                mailtos.add(href)
            elif href.lower().startswith("tel:"):
                tel_links.add(href)
            else:
                enlaces.add(urllib.parse.urljoin(pag["url_final"], href))

        for tag in sopa(["script", "style", "noscript"]):
            tag.decompose()
        texto_visible_total.append(sopa.get_text(" ", strip=True)[:400_000])

    html_cat = "\n".join(html_total)
    texto_cat = "\n".join(texto_visible_total)

    # ---- detectores ----
    resultado["tecnologias"] = detectar_tecnologias(
        html_cat, sorted(scripts), generadores, cabeceras_union, sorted(cookies))

    resultado["contacto"] = {
        "emails": extraer_emails(texto_cat, sorted(mailtos)),
        "telefonos": extraer_telefonos(texto_cat, sorted(tel_links)),
        "redes_sociales": extraer_redes_sociales(sorted(enlaces)),
    }

    # ---- minería profunda del código fuente ----
    mineria, contacto_ld, redes_extra = minar_html(
        [{"url": p["url_final"], "html": p["html"]} for p in paginas_ok],
        principal["url_final"])
    resultado["codigo_fuente"] = mineria
    contactos = resultado["contacto"]

    #   · emails: texto visible ∪ HTML crudo (atributos/JS/JSON) ∪ JSON-LD
    emails_ld = {e.strip().lower() for e in contacto_ld["emails"]}
    contactos["emails"] = sorted(
        set(contactos["emails"]) | emails_ld | set(mineria.get("emails_solo_en_codigo", [])))
    #   · teléfonos desde datos estructurados (confianza alta)
    digitos_actuales = {re.sub(r"\D", "", t["numero"]) for t in contactos["telefonos"]}
    for numero in sorted(contacto_ld["telefonos"]):
        digitos = re.sub(r"\D", "", numero)
        if 7 <= len(digitos) <= 15 and digitos not in digitos_actuales:
            contactos["telefonos"].append(
                {"numero": numero, "tipo": "JSON-LD (datos estructurados)", "confianza": "alta"})
    #   · direcciones físicas desde JSON-LD / geo
    if contacto_ld["direcciones"]:
        contactos["direcciones"] = sorted(contacto_ld["direcciones"])
    #   · redes sociales: enlaces ∪ sameAs ∪ twitter:site
    for enlace in redes_extra:
        for red, urls in extraer_redes_sociales([enlace]).items():
            previas = set(contactos["redes_sociales"].get(red, []))
            contactos["redes_sociales"][red] = sorted(previas | set(urls))
    contactos["redes_sociales"] = dict(sorted(contactos["redes_sociales"].items()))

    #   · enriquecimiento de tecnologías desde el código fuente
    tienda = mineria.get("shopify") or {}
    if tienda.get("dominio_myshopify"):
        tema = tienda.get("tema") or {}
        etiqueta = f"Shopify (tema: {tema.get('nombre', '?')} v{tema.get('version', '?')})"
        resultado["tecnologias"].setdefault("Ecommerce", []).append(etiqueta)
        resultado["tecnologias"].setdefault("CDN y hosting", []).append(
            f"Shopify hosting (subdominio {tienda['dominio_myshopify']})")

    techs_planas = {t for lst in resultado["tecnologias"].values() for t in lst}
    if any(t.startswith("WordPress") for t in techs_planas):
        purl = urllib.parse.urlparse(principal["url_final"])
        info_wp = sondear_wp_json(rastreador.sesion, f"{purl.scheme}://{purl.netloc}", cfg)
        if info_wp:
            resultado["codigo_fuente"]["wordpress_rest"] = info_wp
            for ns in info_wp["namespaces"]:
                plugin = WP_PLUGINS_NS.get(ns.split("/")[0])
                if plugin:
                    resultado["tecnologias"].setdefault("CMS", []).append(plugin)

    for cat, techs in resultado["tecnologias"].items():
        resultado["tecnologias"][cat] = sorted(set(techs))

    # ---- clasificador de categoría de negocio ----
    es_tienda = bool(resultado["tecnologias"].get("Ecommerce")) or any(
        "WooCommerce" in t or "Shopify" in t
        for t in resultado["tecnologias"].get("CMS", []))
    cat_neg = clasificar_negocio(
        texto_cat, mineria.get("metadatos"),
        mineria.get("datos_estructurados_jsonld"), es_tienda)
    # si el catálogo no la identifica (o muy débil), se intenta DESCUBRIR una
    # categoría nueva desde @types sin mapear o palabras dominantes
    if not cat_neg.get("categoria") or cat_neg.get("confianza") == "baja":
        descubierta = descubrir_categoria(
            texto_cat, mineria.get("metadatos"),
            mineria.get("datos_estructurados_jsonld"), es_tienda)
        if descubierta and (not cat_neg.get("categoria")
                            or descubierta["fuente"].startswith("JSON-LD")):
            if cat_neg.get("categoria"):
                descubierta["alternativa_catalogo"] = cat_neg["categoria"]
            cat_neg = descubierta
    resultado["categoria_negocio"] = cat_neg

    exposicion = []
    for pag in paginas_ok[: cfg.max_paginas_exposicion]:
        sopa = BeautifulSoup(pag["html"], "html.parser")
        for tag in sopa(["script", "style"]):
            tag.decompose()
        exposicion += detectar_exposicion(sopa.get_text(" ", strip=True),
                                          pag["html"], pag["url_final"])
    # deduplicar globalmente
    vistos, resultado["exposicion_datos"] = set(), []
    for h in exposicion:
        clave = (h["tipo"], h["valor_enmascarado"])
        if clave not in vistos:
            vistos.add(clave)
            resultado["exposicion_datos"].append(h)

    cab_sec = dict(principal["cabeceras"])
    cab_sec["_esquema_https"] = "sí" if principal["url_final"].startswith("https://") else "no"
    resultado["seguridad_http"] = analizar_seguridad_http(cab_sec)
    resultado["cabeceras_servidor"] = {
        k: v for k, v in cabeceras_union.items()
        if k in ("server", "x-powered-by", "via", "x-generator", "cf-ray")}

    return resultado


# ----------------------------------------------------------------------
# Salidas: JSON, CSV y HTML
# ----------------------------------------------------------------------

def guardar_json(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)


def guardar_csv(resultados, ruta):
    from firmas_tecnologia import CATEGORIAS
    columnas = (["empresa", "sitio", "categoria_negocio", "estado", "emails", "telefonos", "redes_sociales"]
                + CATEGORIAS
                + ["hallazgos_exposicion", "severidad_maxima", "seguridad_http"])
    sev_orden = {"crítica": 4, "alta": 3, "media": 2, "baja": 1}

    with open(ruta, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(columnas)
        for r in resultados:
            tech = r.get("tecnologias", {})
            exp = r.get("exposicion_datos", [])
            sev_max = max((sev_orden.get(h["severidad"], 0) for h in exp), default=0)
            sev_txt = next((k for k, v in sev_orden.items() if v == sev_max), "-")
            fila = {
                "empresa": r.get("empresa") or "",
                "sitio": r.get("url_final", r["url_solicitada"]),
                "categoria_negocio": etiqueta_categoria(r.get("categoria_negocio")),
                "estado": r["estado"],
                "emails": "; ".join(r["contacto"]["emails"]),
                "telefonos": "; ".join(t["numero"] for t in r["contacto"]["telefonos"]),
                "redes_sociales": "; ".join(
                    f"{k}: {v[0]}" for k, v in r["contacto"]["redes_sociales"].items()),
                "hallazgos_exposicion": len(exp),
                "severidad_maxima": sev_txt,
                "seguridad_http": r.get("seguridad_http", {}).get("puntuacion", "-"),
            }
            for cat in CATEGORIAS:
                fila[cat] = "; ".join(tech.get(cat, []))
            w.writerow([fila.get(c, "") for c in columnas])


_CSS = """
body{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#1a1a2e;background:#f7f7fb}
h1{font-size:1.6rem} h2{margin-top:2.2rem;border-bottom:2px solid #6c63ff;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;background:#fff;margin:1rem 0;font-size:.9rem}
th,td{border:1px solid #ddd;padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:#6c63ff;color:#fff}
tr:nth-child(even){background:#f0efff}
.etiqueta{display:inline-block;background:#e8e6ff;border-radius:4px;padding:.1rem .45rem;margin:.1rem;font-size:.85rem}
.etiqueta.cat{background:#d7f5dd;color:#0c5719;font-weight:600;font-size:.95rem}
.sev-critica{background:#ffd6d6;color:#8a0000}.sev-alta{background:#ffe9c7;color:#7a4b00}
.sev-media{background:#fff9c2;color:#6b6200}.sev-baja{background:#d9ecff;color:#064a80}
.aviso{background:#fff3cd;border:1px solid #ffecb5;border-radius:8px;padding:.8rem 1rem;margin:1rem 0}
code{background:#eee;padding:.1rem .3rem;border-radius:4px}
"""


def _esc(s):
    import html as _h
    return _h.escape(str(s))


def _tabla_pares(pares, cabeceras):
    filas = "".join(
        f"<tr><th style='width:220px'>{_esc(k)}</th><td>{v}</td></tr>" for k, v in pares)
    return f"<table><thead><tr>{''.join(f'<th>{_esc(c)}</th>' for c in cabeceras)}</tr></thead><tbody>{filas}</tbody></table>"


def registrar_categorias_nuevas(resultados, ruta):
    """
    Registro acumulativo de categorías descubiertas automáticamente.

    Lee/actualiza <salida>/categorias_descubiertas.json: por cada categoría
    nueva guarda cuántas veces se ha visto, en qué sitios y la fuente del
    descubrimiento, para decidir si merece entrar al catálogo fijo.
    Devuelve la lista de nombres descubiertos en ESTA ejecución.
    """
    registro = {}
    if os.path.exists(ruta):
        try:
            with open(ruta, encoding="utf-8") as f:
                registro = json.load(f)
        except Exception:
            registro = {}
    ahora = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    descubiertas = []
    for r in resultados:
        cat = r.get("categoria_negocio") or {}
        if not (cat.get("nueva") and cat.get("categoria")):
            continue
        nombre = cat["categoria"]
        entrada = registro.get(nombre) or {
            "primera_deteccion": ahora, "veces": 0,
            "fuente": cat.get("fuente", ""), "sitios": []}
        entrada["ultima_deteccion"] = ahora
        entrada["veces"] = int(entrada.get("veces", 0)) + 1
        entrada["fuente"] = cat.get("fuente", entrada.get("fuente", ""))
        sitio = r.get("url_final") or r.get("url_solicitada", "")
        if sitio and sitio not in entrada["sitios"]:
            entrada["sitios"].append(sitio)
        entrada["sitios"] = entrada["sitios"][:25]
        entrada["tienda_online"] = (bool(entrada.get("tienda_online"))
                                    or bool(cat.get("tienda_online")))
        entrada["sugerencia"] = ("Si se repite en varios sitios, agrégala a "
                                 "CATEGORIAS_NEGOCIO en detectores.py con sus "
                                 "palabras clave.")
        registro[nombre] = entrada
        descubiertas.append(nombre)
    if descubiertas:
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(registro, f, ensure_ascii=False, indent=2)
    return sorted(set(descubiertas))


def guardar_html(resultados, ruta):
    partes = [f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Reporte de auditoría web</title><style>{_CSS}</style></head><body>
<h1>🔎 Reporte de auditoría de información pública</h1>
<p>Generado: {_esc(_dt.datetime.now().isoformat(timespec='seconds'))} · Sitios: {len(resultados)}</p>
<div class="aviso">⚠️ <b>Informe confidencial de auditoría.</b> Los datos sensibles
detectados aparecen <b>enmascarados</b>. Usa esta información únicamente para los
fines de la auditoría autorizada y notifica los hallazgos al responsable del sitio.</div>"""]

    for r in resultados:
        sitio = r.get("url_final", r["url_solicitada"])
        titulo = f"🏢 {_esc(r['empresa'])} — {_esc(sitio)}" if r.get("empresa") else f"🌐 {_esc(sitio)}"
        partes.append(f"<h2>{titulo}</h2>")
        estado = _esc(r["estado"])
        partes.append(f"<p><b>Estado:</b> {estado} · <b>Páginas analizadas:</b> "
                      f"{len(r.get('paginas_analizadas', []))} · "
                      f"<b>Seguridad HTTP:</b> {_esc(r.get('seguridad_http', {}).get('puntuacion', '-'))}</p>")
        if r.get("categoria_negocio"):
            catn = r["categoria_negocio"]
            nueva_txt = (f" · 🆕 descubierta automáticamente ({_esc(catn.get('fuente', ''))})"
                         if catn.get("nueva") else "")
            ev = (" · evidencia: " + _esc(", ".join(catn.get("evidencia", [])[:4]))
                  if catn.get("evidencia") else "")
            partes.append(f"<p>🏷️ <b>Categoría detectada:</b> "
                          f"<span class='etiqueta cat'>{_esc(etiqueta_categoria(catn))}</span>"
                          f"<small>{nueva_txt}{ev}</small></p>")

        tech = r.get("tecnologias", {})
        if tech:
            filas = "".join(
                f"<tr><th style='width:220px'>{_esc(cat)}</th><td>"
                + " ".join(f"<span class='etiqueta'>{_esc(t)}</span>" for t in techs)
                + "</td></tr>" for cat, techs in tech.items())
            partes.append(f"<h3>Stack tecnológico</h3><table><tbody>{filas}</tbody></table>")

        cf = r.get("codigo_fuente") or {}
        filas_cf = []
        metas = cf.get("metadatos") or {}
        for k in ("description", "keywords", "og:site_name", "generator",
                  "theme-color", "geo.position", "author", "twitter:site"):
            if metas.get(k):
                filas_cf.append((f"meta {k}", _esc(metas[k])))
        jsonld = cf.get("datos_estructurados_jsonld") or []
        if jsonld:
            tipos = {}
            for o in jsonld:
                tipos[o["tipo"]] = tipos.get(o["tipo"], 0) + 1
            filas_cf.append(("Datos estructurados JSON-LD",
                             _esc(", ".join(f"{t} ×{n}" for t, n in sorted(tipos.items())))))
        if (cf.get("shopify") or {}).get("dominio_myshopify"):
            filas_cf.append(("Shopify (código fuente)",
                             _esc(cf["shopify"]["dominio_myshopify"]
                                  + (" · " + str(cf["shopify"].get("tema", ""))
                                     if cf["shopify"].get("tema") else ""))))
        if cf.get("wordpress_rest"):
            wp = cf["wordpress_rest"]
            filas_cf.append(("WordPress REST API",
                             _esc(f"{wp.get('nombre_sitio') or ''} · tz {wp.get('timezone') or '?'} · "
                                  f"namespaces: {', '.join(wp.get('namespaces', [])[:8])}")))
        if cf.get("formularios"):
            muestra = "; ".join(f"{f['metodo']} {f['accion'][:60]} ({', '.join(f['campos'][:5])})"
                                for f in cf["formularios"][:3])
            filas_cf.append((f"Formularios ({len(cf['formularios'])})", _esc(muestra)))
        if cf.get("feeds"):
            filas_cf.append(("Feeds RSS/Atom",
                             "<br>".join(_esc(f["url"]) for f in cf["feeds"])))
        if cf.get("comentarios_reveladores"):
            filas_cf.append(("Comentarios en el HTML",
                             "<br>".join("🧩 " + _esc(c) for c in cf["comentarios_reveladores"])))
        if filas_cf:
            partes.append("<h3>🧬 Información del código fuente</h3>"
                          + _tabla_pares(filas_cf, ["Clave", "Valor"]))

        # sección libre para hallazgos extraordinarios (auditorías manuales/one-off)
        if r.get("extraccion_adicional"):
            filas_x = [(k, v if "<" in str(v) else _esc(v))
                       for k, v in r["extraccion_adicional"]]
            partes.append("<h3>📌 Hallazgos adicionales</h3>"
                          + _tabla_pares(filas_x, ["Clave", "Valor"]))

        c = r.get("contacto", {})
        filas = []
        if c.get("emails"):
            filas.append(("✉️ Emails", " ".join(f"<span class='etiqueta'>{_esc(e)}</span>" for e in c["emails"])))
        if c.get("telefonos"):
            filas.append(("📞 Teléfonos", " ".join(
                f"<span class='etiqueta'>{_esc(t['numero'])} <small>({_esc(t['confianza'])})</small></span>"
                for t in c["telefonos"])))
        for red, urls in (c.get("redes_sociales") or {}).items():
            filas.append((f"🔗 {_esc(red)}", "<br>".join(
                f"<a href='{_esc(u)}' rel='nofollow noopener'>{_esc(u)}</a>" for u in urls)))
        if filas:
            partes.append("<h3>Contacto</h3>" + _tabla_pares(filas, ["Tipo", "Valor"]))

        exp = r.get("exposicion_datos", [])
        if exp:
            filas = "".join(
                f"<tr><td><span class='etiqueta sev-{_esc(h['severidad'])}'>{_esc(h['severidad'])}</span></td>"
                f"<td>{_esc(h['tipo'])}</td><td><code>{_esc(h['valor_enmascarado'])}</code></td>"
                f"<td><small>{_esc(urllib.parse.urlparse(h['pagina']).path or '/')}</small></td></tr>"
                for h in exp)
            partes.append("<h3>⚠️ Posible exposición de datos sensibles</h3>"
                          f"<table><thead><tr><th>Severidad</th><th>Tipo</th>"
                          f"<th>Valor (enmascarado)</th><th>Página</th></tr></thead><tbody>{filas}</tbody></table>")

    partes.append("</body></html>")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("".join(partes))


# ----------------------------------------------------------------------
# Auto-prueba sin red (valida los detectores con HTML de muestra)
# ----------------------------------------------------------------------

HTML_PRUEBA = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.5">
<meta name="og:site_name" content="Acme Demo Inc">
<meta name="twitter:site" content="@acmedemo">
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
<script src="https://js.stripe.com/v3"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
<link rel="alternate" type="application/rss+xml" href="https://acme-demo.io/feed/">
<script type="application/ld+json">
{"@context": "https://schema.org", "@type": "Organization",
 "name": "Acme Demo Inc", "url": "https://acme-demo.io",
 "email": "info@acme-demo.io", "telephone": "+52 55 0000 1111",
 "sameAs": ["https://www.linkedin.com/company/acme-demo", "https://www.tiktok.com/@acmedemo"],
 "address": {"@type": "PostalAddress", "streetAddress": "Av. Reforma 123",
             "addressLocality": "CDMX", "postalCode": "06600", "addressCountry": "MX"}}
</script>
</head><body>
<!-- This site is optimized with the Yoast SEO plugin v21.0 - https://yoast.com -->
<!-- Tema: AcmeTheme v2.1 por Estudio Creativo Demo -->
<p>Contáctanos: ventas@acme-demo.io o llama al +52 55 1234 5678</p>
<a href="mailto:soporte@acme-demo.io">soporte</a>
<a href="tel:+525512345678">llamar</a>
<a href="https://www.facebook.com/acmedemo">fb</a>
<a href="https://api.whatsapp.com/send?phone=5215512345678">wa</a>
<form action="/contacto/enviar" method="post"><input name="nombre" type="text"><input name="email" type="email"></form>
<p>Transferencias: CLABE interbancaria 002010077777777771 Banco Demo</p>
<p>IBAN: ES91 2100 0418 4502 0005 1332</p>
<p>Tarjeta de prueba expuesta 4111 1111 1111 1111</p>
<script>var k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";</script>
</body></html>"""


def auto_test():
    print("Ejecutando auto-prueba de detectores (sin red)...\n")
    cab = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2",
           "cf-ray": "8ab1c2d3e4-MEX", "set-cookie": "wp-settings-1=x"}
    cookies = ["wp-settings-1", "_ga"]

    tech = detectar_tecnologias(HTML_PRUEBA, ["https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"],
                                ["WordPress 6.5"], cab, cookies)
    emails = extraer_emails(BeautifulSoup(HTML_PRUEBA, "html.parser").get_text(" "),
                            ["mailto:soporte@acme-demo.io"])
    tels = extraer_telefonos(BeautifulSoup(HTML_PRUEBA, "html.parser").get_text(" "),
                             ["tel:+525512345678"])
    redes = extraer_redes_sociales(["https://www.facebook.com/acmedemo",
                                    "https://api.whatsapp.com/send?phone=5215512345678"])
    sopa = BeautifulSoup(HTML_PRUEBA, "html.parser")
    for t in sopa(["script", "style"]):
        t.decompose()
    expo = detectar_exposicion(sopa.get_text(" ", strip=True), HTML_PRUEBA, "https://prueba.local/")
    seg = analizar_seguridad_http({"content-security-policy": "default-src 'self'"})

    # minería profunda del código fuente
    mineria, contacto_ld, redes_extra = minar_html(
        [{"url": "https://prueba.local/", "html": HTML_PRUEBA}], "https://prueba.local/")
    from detectores import minar_shopify, clasificar_negocio
    info_shop = minar_shopify('<script>Shopify.shop = "acme-demo.myshopify.com";'
                              'Shopify.theme = {"name":"Dawn","version":"12.0.0","id":123};</script>')

    # clasificador de vertical de negocio
    texto_cannabis = ("Gomitas THC Delta 9 y CBD 100% legales en México. Vapes, wax, HHC, "
                      "pre-rolls, bongs y smoke shop. Terpenos y cáñamo premium.")
    cat_cnnb = clasificar_negocio(texto_cannabis, {"description": "Compra gomitas THC y CBD"},
                                  [], es_tienda=True)
    cat_pets = clasificar_negocio("venta de croquetas",
                                  {}, [{"tipo": "PetStore"}], es_tienda=True)
    cat_vacia = clasificar_negocio("xyz qqq www", {}, [], es_tienda=False)

    # descubrimiento de categorías NUEVAS
    from detectores import descubrir_categoria
    nueva_ld = descubrir_categoria("xyz qqq www", {},
                                   [{"tipo": "ArtGallery"}], es_tienda=False)
    txt_amig = ("Amigurumis tejidos a mano en crochet. amigurumis "
                "personalizados, patrones de amigurumis kawaii.") * 3
    nueva_kw = descubrir_categoria(
        txt_amig, {"title": "Amigurumis MX | amigurumis de crochet",
                   "description": "venta de amigurumis tejidos"}, [],
        es_tienda=True)
    nada_generico = descubrir_categoria("xyz qqq www", {},
                                        [{"tipo": "WebPage, Organization"}],
                                        es_tienda=False)

    todas = [t for lst in tech.values() for t in lst]
    tipos_exp = {h["tipo"] for h in expo}

    chequeos = [
        ("CMS WordPress detectado", any("WordPress" in t for t in tech.get("CMS", []))),
        ("Cloudflare (CDN) detectado", any("Cloudflare" in t for t in tech.get("CDN y hosting", []))),
        ("nginx (Server) detectado", any("nginx" in t for t in tech.get("Server", []))),
        ("GTM (Analytics) detectado", any("Tag Manager" in t for t in todas)),
        ("Stripe (Payments) detectado", any("Stripe" in t for t in tech.get("Payments", []))),
        ("Google Fonts (Media) detectado", any("Google Fonts" in t for t in tech.get("Media y mapas", []))),
        ("Email del texto extraído", "ventas@acme-demo.io" in emails),
        ("Email de mailto: extraído", "soporte@acme-demo.io" in emails),
        ("Teléfono internacional extraído", any(t["confianza"] == "alta" for t in tels)),
        ("Facebook detectado", "Facebook" in redes),
        ("WhatsApp detectado", "WhatsApp" in redes),
        ("CLABE detectada", any(t.startswith("CLABE") for t in tipos_exp)),
        ("IBAN detectado", any(t.startswith("IBAN") for t in tipos_exp)),
        ("Tarjeta Luhn detectada", any("tarjeta" in t for t in tipos_exp)),
        ("sk_live detectada y enmascarada",
         any(h["tipo"].startswith("Clave secreta de Stripe")
             and h["valor_enmascarado"].startswith("sk_l")
             and h["valor_enmascarado"].endswith("dc")
             and "***" in h["valor_enmascarado"]
             for h in expo)),
        ("Ningún valor sensible sin enmascarar (ni en contexto)",
         all("4111111111111111" not in json.dumps(h, ensure_ascii=False)
             and "sk_live_4eC39HqLyjWDarjtT1zdp7dc" not in json.dumps(h, ensure_ascii=False)
             and "002010077777777771" not in json.dumps(h, ensure_ascii=False)
             and "ES9121000418450200051332" not in json.dumps(h, ensure_ascii=False)
             for h in expo)),
        ("CSP reportada", "CSP" in seg["presentes"] and "HSTS" in seg["ausentes"]),
        ("Meta og:site_name minado", mineria["metadatos"].get("og:site_name") == "Acme Demo Inc"),
        ("twitter:site -> red de X", "https://x.com/acmedemo" in redes_extra),
        ("JSON-LD: email extraído", "info@acme-demo.io" in contacto_ld["emails"]),
        ("JSON-LD: teléfono extraído", "+52 55 0000 1111" in contacto_ld["telefonos"]),
        ("JSON-LD: dirección extraída", any("Reforma" in d for d in contacto_ld["direcciones"])),
        ("JSON-LD: sameAs (LinkedIn/TikTok)",
         any("linkedin" in r for r in contacto_ld["redes"]) and any("tiktok" in r for r in contacto_ld["redes"])),
        ("Comentario Yoast detectado", any("Yoast SEO plugin" in c for c in mineria["comentarios_reveladores"])),
        ("Formulario detectado", any(f["accion"].endswith("/contacto/enviar") for f in mineria["formularios"])),
        ("Feed RSS detectado", any(f["url"].endswith("/feed/") for f in mineria["feeds"])),
        ("Shopify: dominio myshopify minado", info_shop.get("dominio_myshopify") == "acme-demo.myshopify.com"),
        ("Shopify: tema minado", (info_shop.get("tema") or {}).get("nombre") == "Dawn"),
        ("Clasificador: cannabis/CBD detectado (alta)",
         cat_cnnb["categoria"] == "Cannabis / CBD y smoke shop" and cat_cnnb["confianza"] == "alta"),
        ("Clasificador: marca tienda online", cat_cnnb["tienda_online"] is True),
        ("Clasificador: PetStore JSON-LD -> Mascotas",
         cat_pets["categoria"] == "Mascotas" and cat_pets["confianza"] == "alta"),
        ("Clasificador: sin señal -> no identificada", cat_vacia["categoria"] is None),
        ("Descubrimiento: @type desconocido -> categoría nueva [media]",
         nueva_ld is not None and nueva_ld.get("nueva")
         and nueva_ld["categoria"] == "Art gallery"
         and nueva_ld["confianza"] == "media"),
        ("Descubrimiento: palabras dominantes -> categoría nueva [baja]",
         nueva_kw is not None and nueva_kw.get("nueva")
         and "amigurumi" in nueva_kw["categoria"].lower()
         and nueva_kw["tienda_online"] is True),
        ("Descubrimiento: tipos genéricos NO generan categoría",
         nada_generico is None),
    ]

    fallos = 0
    for nombre, ok in chequeos:
        print(f"  [{'OK' if ok else 'FALLO'}] {nombre}")
        fallos += 0 if ok else 1
    print(f"\n{'✅ Todas las pruebas pasaron' if fallos == 0 else f'❌ {fallos} pruebas fallaron'}"
          f" ({len(chequeos) - fallos}/{len(chequeos)})")
    return 0 if fallos == 0 else 1


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Auditor de información pública de sitios web "
                    "(stack tecnológico, contactos y exposición de datos).")
    ap.add_argument("lista", nargs="?",
                    help="Archivo de URLs: .txt (una por línea) o .csv/.tsv con una "
                         "columna de sitios web (ej. empresas.txt, empresas_y_sitios_web.csv)")
    ap.add_argument("--salida", "-o", default="salida", help="Carpeta de resultados (defecto: salida/)")
    ap.add_argument("--max-paginas", type=int, default=12,
                    help="Páginas internas máx. por sitio (defecto: 12)")
    ap.add_argument("--max-paginas-exposicion", type=int, default=12,
                    help="Páginas máx. donde buscar datos sensibles (defecto: 12)")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Segundos entre peticiones al mismo sitio (defecto: 1.0)")
    ap.add_argument("--timeout", type=float, default=15.0, help="Timeout por petición (defecto: 15s)")
    ap.add_argument("--ignorar-robots", action="store_true",
                    help="No respetar robots.txt (úsalo solo en sitios propios/autorizados)")
    ap.add_argument("--inseguro", action="store_true", help="No verificar certificados TLS")
    ap.add_argument("--user-agent", default=UA_DEFECTO, help="User-Agent identificativo")
    ap.add_argument("--auto-test", action="store_true", help="Ejecuta la auto-prueba sin red y sale")
    args = ap.parse_args(argv)

    if args.auto_test:
        return auto_test()

    if not args.lista:
        ap.error("falta el archivo de URLs (o usa --auto-test)")

    lugares = cargar_lugares(args.lista)
    if not lugares:
        print("⚠️  No se encontraron URLs en el archivo. Formatos admitidos: .txt "
              "(una por línea) o .csv/.tsv con una columna de sitios web.")
        return 2

    os.makedirs(args.salida, exist_ok=True)
    print(f"🚀 Auditoría de {len(lugares)} sitio(s) · salida en '{args.salida}/'")
    if not args.ignorar_robots:
        print("   robots.txt: RESPETADO (usa --ignorar-robots solo con autorización)")

    resultados = []
    for i, lugar in enumerate(lugares, 1):
        url, empresa = lugar["url"], lugar.get("empresa")
        etiqueta = f"{empresa} <{url}>" if empresa else url
        print(f"\n[{i}/{len(lugares)}] {etiqueta}")
        try:
            res = auditar_sitio(url, args, empresa=empresa)
        except Exception as e:  # nunca abortar el lote completo
            res = {"url_solicitada": url, "empresa": empresa, "estado": f"error inesperado: {e}",
                   "tecnologias": {}, "contacto": {"emails": [], "telefonos": [], "redes_sociales": {}},
                   "exposicion_datos": [], "paginas_analizadas": [], "paginas_con_error": []}
        resultados.append(res)

        n_tech = sum(len(v) for v in res.get("tecnologias", {}).values())
        n_exp = len(res.get("exposicion_datos", []))
        c = res.get("contacto", {})
        print(f"      ✔ {res['estado']} | tecnologías: {n_tech} | emails: {len(c.get('emails', []))} "
              f"| teléfonos: {len(c.get('telefonos', []))} | redes: {len(c.get('redes_sociales', {}))} "
              f"| exposición: {n_exp}")

        slug = re.sub(r"[^a-z0-9]+", "-", host_base(res.get("url_final", url))).strip("-") or f"sitio-{i}"
        guardar_json(res, os.path.join(args.salida, f"{slug}.json"))
        time.sleep(args.delay)

    guardar_json(resultados, os.path.join(args.salida, "resultado_completo.json"))
    guardar_csv(resultados, os.path.join(args.salida, "resumen.csv"))
    guardar_html(resultados, os.path.join(args.salida, "reporte.html"))
    nuevas = registrar_categorias_nuevas(
        resultados, os.path.join(args.salida, "categorias_descubiertas.json"))

    print("\n📦 Archivos generados:")
    print(f"   • {args.salida}/reporte.html            (reporte visual consolidado)")
    print(f"   • {args.salida}/resumen.csv             (tabla consolidada, abre en Excel)")
    print(f"   • {args.salida}/resultado_completo.json (JSON con todo el detalle)")
    print(f"   • {args.salida}/<dominio>.json          (un JSON detallado por sitio)")
    if nuevas:
        print(f"\n🆕 Categorías NUEVAS descubiertas ({len(nuevas)}): "
              f"{', '.join(nuevas)}")
        print(f"   • {args.salida}/categorias_descubiertas.json "
              f"(registro acumulativo; si alguna se repite, agrégala a "
              f"CATEGORIAS_NEGOCIO en detectores.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
