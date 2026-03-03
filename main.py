import re
import yaml
from Analise.IP import analisa_ip
from Analise.porta import analisa_porta
from Analise.User import analisa_user
from Analise.pid import analisa_pid
from Analise.Servidor import analisa_servidor
from Analise.contexto import analisar_contexto

# Padrão de Analise
# Data | Hora | IP de requisicao | IP de Destino | Serviço | Porta | Protocolo | Username | Hostname
# Tipo de log: Erro, acesso, alteração, requisição

#Parametros de analise
#Usuarios já conhecidos: root, admin, theo, serginho
#IPs já conhecidos: "203.190.22.1", "91.200.14.88", "189.77.12.5"
IPs = ["203.190.22.1", "91.200.14.88", "189.77.12.5"]
Portas_padrao = [22]
Usuarios = ["root", "admin", "theo", "serginho"]
servidores = ["server01"]

# Variavel de abertura do arquivo de logs
log_file = open('logs.txt', 'r')

# Leitura de linha dentro de uma array, cada linha é um index da array
logs = log_file.readlines() 
data = {}
contador_tentativas = {}
eventos_agregados = {}


# Bloco de Analise de usuarios
#Feb 24 10:00:26 server01 sshd[1032]: Invalid user test from 45.83.12.77 port 60112
#Feb 24 10:00:33 server01 sshd[1035]: Failed password for maria from 191.32.88.10 port 49821 ssh2
#Feb 24 10:00:40 server01 sshd[1038]: Accepted password for maria from 191.32.88.10 port 49822 ssh2
# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# Bloco de Criticidade
# --------------------------------------------------------------------------------------------------------------------
def criticidade(usuario, ip_origem, porta, contexto, tentativas=1):
    score = 0

    # ----------------------------
    # Classificação de IP
    # ----------------------------
    if ip_origem in IPs:
        score += 1   # IP conhecido
    else:
        score += 4   # IP desconhecido

    # ----------------------------
    # Classificação de Usuário
    # ----------------------------
    if usuario in Usuarios:
        score += 1   # Usuário conhecido
    else:
        score += 4   # Usuário inexistente/desconhecido

    # ----------------------------
    # Contexto de autenticação
    # ----------------------------
    pesos_contexto = {
        "senha_errada": 1,
        "senha_correta": 3,
        "acesso_negado": 3,
        "conexao_fechada": 1
    }

    score += pesos_contexto.get(contexto, 0)

    # ----------------------------
    # Porta não padrão (desvio adicional)
    # ----------------------------
    if porta not in Portas_padrao:
        score += 1

    # ----------------------------
    # Ataque por força bruta
    # ----------------------------
    if tentativas >= 5:
        score += 5

    return score

def classificar_criticidade(score):
    if score >= 14:
        return "CRITICO"
    elif score >= 10:
        return "ALTO"
    elif score >= 6:
        return "MEDIA"
    else:
        return "BAIXA"


# --------------------------------------------------------------------------------------------------------------------
# Bloco de analise geral
# --------------------------------------------------------------------------------------------------------------------

def analisa_geral(logs):
        result = {
            "Usario": analisa_user(logs),
            "Endereco Servidor": analisa_servidor(logs),
            "IP de Origem": analisa_ip(logs),
            "porta de Conexao": analisa_porta(logs),
            "PID:" : analisa_pid(logs),
            "Contexto": analisar_contexto(logs)
        }

        return result
        

for log in logs:
    analise_por_campo = analisa_geral(log)

    usuario = analise_por_campo["Usario"]
    ip_origem = analise_por_campo["IP de Origem"]
    contexto = analise_por_campo["Contexto"]
    endereco_servidor = analise_por_campo["Endereco Servidor"]
    porta = analise_por_campo["porta de Conexao"]
    pid = analise_por_campo["PID:"]

    # ----------------------------------------
    # Chave principal de agregação
    # ----------------------------------------
    chave_evento = (usuario, ip_origem, contexto, endereco_servidor)

    if chave_evento not in eventos_agregados:
        eventos_agregados[chave_evento] = {
            "Usario": usuario,
            "Endereco Servidor": endereco_servidor,
            "IP de Origem": ip_origem,
            "Resumo do Log": contexto,
            "Tentativas": 1,
            "Portas": [porta],
            "PIDs": [pid]
        }
    else:
        eventos_agregados[chave_evento]["Tentativas"] += 1

        # Adiciona porta apenas se for diferente
        if porta not in eventos_agregados[chave_evento]["Portas"]:
            eventos_agregados[chave_evento]["Portas"].append(porta)

        # Mesmo critério para PID
        if pid not in eventos_agregados[chave_evento]["PIDs"]:
            eventos_agregados[chave_evento]["PIDs"].append(pid)


# ----------------------------------------
# Aplicar criticidade após agregação
# ----------------------------------------

for i, (chave, evento) in enumerate(eventos_agregados.items()):
    usuario, ip_origem, contexto, endereco_servidor = chave

    evento["Criticidade"] = classificar_criticidade(
        criticidade(
            usuario,
            ip_origem,
            evento["Portas"][0],  # Porta principal (primeira)
            contexto,
            evento["Tentativas"]
        )
    )

    data[i] = evento


with open("file.yaml", "w") as file:
    yaml.dump(data, file)
