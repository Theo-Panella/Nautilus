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
logs = log_file.readlines() #
data = {}

# Bloco de Analise de usuarios
#Feb 24 10:00:26 server01 sshd[1032]: Invalid user test from 45.83.12.77 port 60112
#Feb 24 10:00:33 server01 sshd[1035]: Failed password for maria from 191.32.88.10 port 49821 ssh2
#Feb 24 10:00:40 server01 sshd[1038]: Accepted password for maria from 191.32.88.10 port 49822 ssh2
# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# Bloco de Criticidade
# --------------------------------------------------------------------------------------------------------------------
def criticidade(usuario, ip_origem, porta, contexto):
    score = 0
    agravantes = 0

    # ----------------------------
    # Peso baseado no contexto
    # ----------------------------
    pesos_contexto = {
        "usuario inexistente": 4,
        "Acesso Negado": 3,
        "Conexão fechada": 1,
        "Acesso aceito": 1
    }

    score += pesos_contexto.get(contexto, 0)

    # ----------------------------
    # Desvio de usuário
    # ----------------------------
    if usuario not in Usuarios:
        score += 2
        agravantes += 1

    if usuario in ["root", "admin"]:
        score += 3

    # ----------------------------
    # Desvio de IP
    # ----------------------------
    if ip_origem not in IPs:
        score += 2
        agravantes += 1

    # ----------------------------
    # Desvio de porta
    # ----------------------------
    if porta not in Portas_padrao:
        score += 1
        agravantes += 1

    # ----------------------------
    # Agravante por múltiplos desvios
    # ----------------------------
    if agravantes >= 2:
        score += 2   # penalidade adicional por comportamento anômalo composto

    if agravantes == 3:
        score += 2   # risco crítico por múltiplos vetores alterados

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
        


for c in range(len(logs)):
    analise_por_campo = analisa_geral(logs[c])
    newdata = {
        c: {
        "Usario": analise_por_campo["Usario"],
        "Endereco Servidor": analise_por_campo["Endereco Servidor"],
        "IP de Origem": analise_por_campo["IP de Origem"],
        "porta de Conexao": analise_por_campo["porta de Conexao"],
        "PID:" : analise_por_campo["PID:"],
        "Resumo do Log": analise_por_campo["Contexto"],
        "Criticidade": classificar_criticidade(criticidade(analise_por_campo["Usario"], analise_por_campo["IP de Origem"], analise_por_campo["porta de Conexao"], analise_por_campo["Contexto"]))
        }}

    data.update(newdata)

with open("file.yaml","w") as file:
    yaml.dump(data, file)
