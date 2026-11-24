import os
import re
import secrets
import sqlite3
import threading

from flask import Flask, abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash
from werkzeug.serving import WSGIRequestHandler



class HandlerSeguro(WSGIRequestHandler):
    """CORRECCION: no revelar versiones de Werkzeug/Python en la cabecera Server."""

    def version_string(self):
        return "webserver"


app = Flask(__name__)

# CORRECCION: clave secreta para firmar la sesión (no más cookie en texto plano)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# CORRECCION: flags de seguridad en la cookie de sesión
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript no puede leer la cookie (mitiga robo por XSS)
    SESSION_COOKIE_SAMESITE="Strict",  # El navegador no la envía desde otros sitios (mitiga CSRF)
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # Activar =1 si hay HTTPS
)

DB = "vulnerable.db"
MAX_BIO = 200

# ---------------------------------------------------------------------------
# MONITORIZACION: contadores de eventos de seguridad expuestos en /metrics
# (formato Prometheus) para visualizarlos en Grafana.
# ---------------------------------------------------------------------------
EVENTOS = {
    "login_ok": 0,
    "login_fallido": 0,
    "sqli_sospechoso": 0,
    "xss_sospechoso": 0,
    "csrf_bloqueado": 0,
}
_lock = threading.Lock()

# Patrones simples de DETECCION (no bloquean: la defensa real son las consultas
# parametrizadas y el autoescape; esto solo registra el intento como incidente).
PATRON_SQLI = re.compile(r"('|--|;|/\*|\bunion\b|\bselect\b|\bor\b\s+\S+\s*=)", re.I)
PATRON_XSS = re.compile(r"<\s*/?\s*(script|img|iframe|svg|body|a)\b|javascript:|on\w+\s*=", re.I)


def registrar(tipo):
    with _lock:
        EVENTOS[tipo] += 1


def db_query(query, params=()):
    """CORRECCION SQLi: consultas parametrizadas (los datos nunca se concatenan al SQL)."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


LOGIN_HTML = """
<h2>Login del Sistema Académico</h2>
{% if error %}<p><b>{{ error }}</b></p>{% endif %}
<form method="post">
    Usuario: <input type="text" name="username" maxlength="50" required><br>
    Password: <input type="password" name="password" maxlength="128" required><br>
    <input type="submit" value="Ingresar">
</form>
"""

# CORRECCION XSS: plantilla con autoescape de Jinja2 ({{ }}) en vez de f-strings
DASHBOARD_HTML = """
<h1>Panel de {{ datos['username'] }}</h1>
<p><b>Rol:</b> {{ datos['rol'] }}</p>
<p><b>Biografía:</b> {{ datos['bio'] }}</p>
<hr>
<h3>Actualizar Biografía</h3>
<form action="/update_bio" method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="text" name="nueva_bio" placeholder="Escribe algo..." maxlength="200">
    <input type="submit" value="Guardar Cambios">
</form>
<br>
<form action="/logout" method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="submit" value="Cerrar Sesión">
</form>
"""


def csrf_valido():
    enviado = request.form.get("csrf_token", "")
    esperado = session.get("csrf_token", "")
    return bool(esperado) and secrets.compare_digest(enviado.encode(), esperado.encode())


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()[:50]
        pw = request.form.get("password", "")[:128]

        if PATRON_SQLI.search(user) or PATRON_SQLI.search(pw):
            registrar("sqli_sospechoso")
            app.logger.warning("INTENTO_SQLI user=%r ip=%s", user, request.remote_addr)

        rows = db_query("SELECT username, password FROM usuarios WHERE username = ?", (user,))
        if rows and check_password_hash(rows[0]["password"], pw):
            session.clear()
            session["user"] = rows[0]["username"]
            session["csrf_token"] = secrets.token_hex(16)
            registrar("login_ok")
            app.logger.info("LOGIN_OK user=%r ip=%s", user, request.remote_addr)
            return redirect("/dashboard")

        registrar("login_fallido")
        app.logger.warning("LOGIN_FALLIDO user=%r ip=%s", user, request.remote_addr)
        return render_template_string(LOGIN_HTML, error="Acceso denegado"), 401

    return render_template_string(LOGIN_HTML, error=None)


@app.route("/dashboard")
def dashboard():
    username = session.get("user")
    if not username:
        return redirect("/login")

    rows = db_query("SELECT username, rol, bio FROM usuarios WHERE username = ?", (username,))
    if not rows:
        session.clear()
        return redirect("/login")

    return render_template_string(
        DASHBOARD_HTML, datos=rows[0], csrf_token=session["csrf_token"]
    )


@app.route("/update_bio", methods=["POST"])
def update_bio():
    username = session.get("user")
    if not username:
        return redirect("/login")

    # CORRECCION CSRF: se exige el token anti-CSRF
    if not csrf_valido():
        registrar("csrf_bloqueado")
        app.logger.warning("CSRF_BLOQUEADO user=%r ip=%s", username, request.remote_addr)
        abort(403)

    nueva_bio = request.form.get("nueva_bio", "").strip()[:MAX_BIO]
    if PATRON_XSS.search(nueva_bio):
        registrar("xss_sospechoso")
        app.logger.warning("INTENTO_XSS user=%r ip=%s", username, request.remote_addr)
    db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect("/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    if not csrf_valido():
        registrar("csrf_bloqueado")
        app.logger.warning("CSRF_BLOQUEADO (logout) ip=%s", request.remote_addr)
        abort(403)
    session.clear()
    return redirect("/login")


@app.route("/metrics")
def metrics():
    """Metricas en formato de texto Prometheus."""
    lineas = [
        "# HELP lab_incidentes_total Incidentes de seguridad detectados, por tipo.",
        "# TYPE lab_incidentes_total counter",
    ]
    with _lock:
        for tipo in ("login_fallido", "sqli_sospechoso", "xss_sospechoso", "csrf_bloqueado"):
            lineas.append('lab_incidentes_total{tipo="%s"} %d' % (tipo, EVENTOS[tipo]))
        lineas += [
            "# HELP lab_login_ok_total Inicios de sesion exitosos.",
            "# TYPE lab_login_ok_total counter",
            "lab_login_ok_total %d" % EVENTOS["login_ok"],
        ]
    cuerpo = "\n".join(lineas) + "\n"
    return cuerpo, 200, {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}


@app.route("/")
def home():
    return redirect("/login")


if __name__ == "__main__":
    # CORRECCION: debug desactivado; el host se define por variable de entorno
    app.run(
        debug=False,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=5000,
        request_handler=HandlerSeguro,
    )
