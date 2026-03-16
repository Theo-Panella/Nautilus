from flask import Flask, render_template, request, redirect, session, jsonify
from database.db import get_db
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = "nerdy_secret"

# --------------------- RATE LIMITING (em memória) ---------------------
# { ip: { "tentativas": N, "bloqueado_ate": datetime ou None } }
_tentativas = {}
LIMITE_TENTATIVAS = 5
BLOQUEIO_MINUTOS  = 2

def verificar_bloqueio(ip):
    """Retorna (bloqueado: bool, segundos_restantes: int)"""
    info = _tentativas.get(ip)
    if not info:
        return False, 0
    ate = info.get("bloqueado_ate")
    if ate and datetime.now() < ate:
        restam = int((ate - datetime.now()).total_seconds())
        return True, restam
    return False, 0

def registrar_falha(ip):
    """Incrementa falhas e bloqueia se atingir o limite."""
    if ip not in _tentativas:
        _tentativas[ip] = {"tentativas": 0, "bloqueado_ate": None}
    # reset se bloqueio anterior já expirou
    ate = _tentativas[ip].get("bloqueado_ate")
    if ate and datetime.now() >= ate:
        _tentativas[ip] = {"tentativas": 0, "bloqueado_ate": None}
    _tentativas[ip]["tentativas"] += 1
    if _tentativas[ip]["tentativas"] >= LIMITE_TENTATIVAS:
        _tentativas[ip]["bloqueado_ate"] = datetime.now() + timedelta(minutes=BLOQUEIO_MINUTOS)
        _tentativas[ip]["tentativas"] = 0

def limpar_falhas(ip):
    """Limpa contagem após login bem-sucedido."""
    if ip in _tentativas:
        del _tentativas[ip]


# --------------------- HOME ---------------------
@app.route("/")
def index():
    return render_template("index.html")


# --------------------- LOGIN ---------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]
        ip = request.remote_addr

        # ── Checa bloqueio ──────────────────────
        bloqueado, restam = verificar_bloqueio(ip)
        if bloqueado:
            minutos = restam // 60
            segundos = restam % 60
            erro = f"IP bloqueado por tentativas excessivas. Aguarde {minutos:02d}:{segundos:02d}."
            return render_template("login.html", erro=erro, bloqueado=True, restam=restam)

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM users WHERE usuario=? AND senha=?",
            (usuario, senha)
        )
        user = cur.fetchone()

        if user:
            limpar_falhas(ip)
            session["user"] = usuario
            session["user_id"] = user[0]

            log(usuario, ip, "sucesso")
            return redirect("/parabens")
        
        else:
            registrar_falha(ip)
            bloqueado2, restam2 = verificar_bloqueio(ip)
            if bloqueado2:
                erro = f"Muitas tentativas! IP bloqueado por {BLOQUEIO_MINUTOS} minutos."
                return render_template("login.html", erro=erro, bloqueado=True, restam=restam2)
            info = _tentativas.get(ip, {})
            tentativas_feitas = info.get("tentativas", 0)
            faltam = LIMITE_TENTATIVAS - tentativas_feitas
            log(usuario, ip, "falha")
            return render_template("login.html", erro=f"Usuário ou senha inválidos. ({faltam} tentativa(s) restante(s) antes do bloqueio)")

    return render_template("login.html")


# --------------------- PÁGINA USUÁRIO COMUM ---------------------
@app.route("/parabens")
def parabens():

    if "user" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]

    ip = request.remote_addr

    return render_template(
        "parabens.html",
        usuario=session["user"],
        total_logs=total_logs,
        ip=ip
    )


# --------------------- REGISTRAR LOG ---------------------
def log(usuario, ip, status):

    data = datetime.now()

    if status == "falha":
        evento = "Failed password"
    else:
        evento = "Accepted password"

    # informações extras do request
    metodo = request.method
    endpoint = request.path
    user_agent = request.headers.get("User-Agent")

    raw_log = (
        f"{data.strftime('%b %d %H:%M:%S')} nerdy-web "
        f"flask[{os.getpid()}]: {evento} for {usuario} "
        f"from {ip} port 443 "
        f'method={metodo} endpoint="{endpoint}" '
        f'user-agent="{user_agent}"'
    )

    db = get_db()
    cur = db.cursor()

    cur.execute("""
    INSERT INTO logs(usuario, ip, data, status, raw_log)
    VALUES(?,?,?,?,?)
    """, (usuario, ip, data, status, raw_log))

    db.commit()


# --------------------- API STATUS BLOQUEIO ---------------------
@app.route("/check_block")
def check_block():
    ip = request.remote_addr
    bloqueado, restam = verificar_bloqueio(ip)
    return jsonify({"bloqueado": bloqueado, "restam": restam})

# --------------------- LOGOUT ---------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# --------------------- INICIAR SERVIDOR ---------------------
if __name__ == "__main__":
    app.run(debug=True)