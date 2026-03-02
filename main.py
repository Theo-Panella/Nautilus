import re
from datetime import *
from time import strftime
import yaml


# Padrão de Analise
# Data | Hora | IP de requisicao | IP de Destino | Serviço | Porta | Protocolo | Username | Hostname
# Tipo de log: Erro, acesso, alteração, requisição

#Parametros de analise
#Usuarios já conhecidos: root, admin, theo, serginho
#IPs já conhecidos: "203.190.22.1", "91.200.14.88", "189.77.12.5"
IPs = ["203.190.22.1", "91.200.14.88", "189.77.12.5"]
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
#def analisa_usuario_falha(usuario):
#    result = re.search("Failed password for (.*) from", usuario)
#    if result:
#        return result.group(1)
#    else:
#        return "Usuario invalido"
#        
#
#def analisa_usuario_invalido(usuario):
#    result = re.search("Invalid user (.*) from", usuario)
#    if result:
#        return result.group(1)
#    else:
#        return "Usuario invalido"

def analisa_user(logs):
    #for result in logs:
        if re.search("Failed password for.*", logs):
            log_wrong_passwd = re.search("Failed password for (.*) from", logs)
            if log_wrong_passwd:
                return log_wrong_passwd.group(1)
            
        elif re.search("Connection closed by authenticating user.*", logs):
            log_connec_close = re.search(f"Connection closed by authenticating user (.*) .* port .*", logs)
            if log_connec_close:
                return log_connec_close.group(1)

        elif re.search("Invalid user.*", logs):
            log_invalid_user = re.search("Invalid user (.*) from", logs)
            #print("Failed login attempt for invalid user:", log_invalid_user)
            if log_invalid_user:
                return log_invalid_user.group(1)

        elif re.search("Accepted password for.*", logs):
            #print("Successful login for user:", re.search(f"Accepted password for (.*) from", result).group(1))
            return re.search(f"Accepted password for (.*) from", logs).group(1)
# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# Bloco de analise do servidor
# --------------------------------------------------------------------------------------------------------------------
def analisa_servidor(logs):
    servidor = logs.split(" ")
    return servidor[3]
             

# --------------------------------------------------------------------------------------------------------------------
# Bloco de analise de IPs, portas e PID
# --------------------------------------------------------------------------------------------------------------------
def analisa_ip(logs):
    #for result in logs:
        if re.search("Failed password for.*", logs):
            log_wrong_passwd_ip = re.search("Failed password for.* from (.*) port", logs)
            if log_wrong_passwd_ip:
                return log_wrong_passwd_ip.group(1)
        
        elif re.search("Connection closed by authenticating user.*", logs):
            log_connec_close = re.search(f"Connection closed by authenticating user.* (.*) port .*", logs)
            if log_connec_close:
                return log_connec_close.group(1)

        elif re.search("Invalid user.*", logs):
            log_invalid_user_ip = re.search("Invalid user.* from (.*) port", logs)
            if log_invalid_user_ip:
                return log_invalid_user_ip.group(1)

        elif re.search("Accepted password for.*", logs):
            log_successful_login_ip = re.search("Accepted password for.* from (.*) port", logs)
            if log_successful_login_ip:
                return log_successful_login_ip.group(1)
            
def analisa_porta(logs):
    #for result in logs:
        if re.search("Failed password for.*", logs):
            log_wrong_passwd_port = re.search("Failed password for.* port (.*) ssh2", logs)
            if log_wrong_passwd_port:
                return log_wrong_passwd_port.group(1)
            
        elif re.search("Connection closed by authenticating user.*", logs):
            log_connec_close = re.search(f"Connection closed by authenticating user.* port (.*)", logs)
            if log_connec_close:
                return log_connec_close.group(1)

        elif re.search("Invalid user.*", logs):
            log_invalid_user_port = re.search("Invalid user.* port (.*)", logs)
            if log_invalid_user_port:
                return log_invalid_user_port.group(1) 

        elif re.search("Accepted password for.*", logs):
            log_successful_login_port = re.search("Accepted password for.* port (.*) ssh2", logs)
            if log_successful_login_port:
                return log_successful_login_port.group(1)

def analisa_pid(logs):
    #for result in logs:
        pid = re.search("sshd\[(.*)\]:", logs)
        if pid:
            return pid.group(1)
# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# Bloco de Criticidade
# --------------------------------------------------------------------------------------------------------------------
##################TERMINAR######################
def criticidade(Usuario, IP_origem, porta):
    #score = ponto + qtd
    ponto = 0
    # qtd += 1
    for usuarios_array in Usuarios:
        if usuarios_array != Usuario:
            ponto += 1
##################TERMINAR######################



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
        "Criticidade": criticidade(analise_por_campo["Usario"], analise_por_campo["IP de Origem"], analise_por_campo["porta de Conexao"])
        }}

    data.update(newdata)

    with open("file.yaml","w") as file:
        yaml.dump(data, file)

    print(newdata)