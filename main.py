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
# Bloco de analise de usuarios
# --------------------------------------------------------------------------------------------------------------------
def analisa_user(logs):
    #for result in logs:
        if re.search("Failed password for.*", logs):
            log_wrong_passwd = re.search("Failed password for (.*) from", logs)
            if log_wrong_passwd:
                return log_wrong_passwd.group(1)

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
# Bloco de analise de IPs, portas e PID
# --------------------------------------------------------------------------------------------------------------------
def analisa_ip(logs):
        if re.search("Failed password for.*", logs):
            log_wrong_passwd_ip = re.search("Failed password for.* from (.*) port", logs)
            if log_wrong_passwd_ip:
                return log_wrong_passwd_ip.group(1)

        elif re.search("Invalid user.*", logs):
            log_invalid_user_ip = re.search("Invalid user.* from (.*) port", logs)
            if log_invalid_user_ip:
                return log_invalid_user_ip.group(1)

        elif re.search("Accepted password for.*", logs):
            log_successful_login_ip = re.search("Accepted password for.* from (.*) port", logs)
            if log_successful_login_ip:
                return log_successful_login_ip.group(1)
            
def analisa_porta(logs):
        if re.search("Failed password for.*", logs):
            log_wrong_passwd_port = re.search("Failed password for.* port (.*) ssh2", logs)
            if log_wrong_passwd_port:
                return log_wrong_passwd_port.group(1)

        elif re.search("Invalid user.*", logs):
            log_invalid_user_port = re.search("Invalid user.* port (.*) ssh2", logs)
            if log_invalid_user_port:
                return log_invalid_user_port.group(1) 

        elif re.search("Accepted password for.*", logs):
            log_successful_login_port = re.search("Accepted password for.* port (.*) ssh2", logs)
            if log_successful_login_port:
                return log_successful_login_port.group(1)

def analisa_pid(logs):
    #for result in logs:
        pid = re.search("sshd\[(.*)\]", logs)
        if pid:
            return pid.group(1)
# --------------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------------
# Bloco de analise de Criticidade
# --------------------------------------------------------------------------------------------------------------------
def analisa_criticidade(logs):
    criticidade = 0
    if (analisa_user(logs) not in Usuarios or analisa_ip(logs) not in IPs):
        criticidade += 4
        if re.search("Failed password for.*", logs):
            criticidade += 3    
        elif re.search("Invalid user.*", logs):
            criticidade += 2
        elif re.search("Accepted password for.*", logs):
            criticidade += 1
    else:
        criticidade += 1
    
    return criticidade

# --------------------------------------------------------------------------------------------------------------------
# Bloco de analise geral
# --------------------------------------------------------------------------------------------------------------------
def analisa_geral(logs):
        return {
            "Usario": analisa_user(logs),
            "IP de acesso": analisa_ip(logs),
            "porta de acesso": analisa_porta(logs),
            "PID:" : analisa_pid(logs),
            "Criticidade": (analisa_criticidade(logs))
        }



for c in range(len(logs)):
    newdata = {
        c: {
        **analisa_geral(logs[c]) # Desconpacta o dicionário e retorna equivalente a cada linha
        }}

    data.update(newdata)

    with open("file.yaml","w") as file:
        yaml.dump(data, file)