# --------------------------------------------------------
# Pega os dados de logs e os organiza em um arquivo yaml
# --------------------------------------------------------

# Padrão de Analise
# Data | Hora | IP de requisicao | IP de Destino | Serviço | Porta | Protocolo | Username | Hostname
# Tipo de log: Erro, acesso, alteração, requisição

import datetime
from time import strftime
import yaml
import re

file = open('logs.txt', 'r')
data = {}
logs = file.readlines() #Pega o dia (primeiro valor do log) e coloca o resultado na array logs array
usuarios = ["root", "admin", "theo", "serginho", "roberto", "maria", "joao", "pedro", "lucas", "ana"]
nome_servicos = ["sshd.*", "http.*", "https.*", "ftp.*", "nginx.*", "smtp.*", "dns.*", "dhcp.*", "vpn.*", "proxy.*", "firewall.*","kernel.*", "cron.*", "systemd.*", "network.*", "database.*", "application.*", "security.*", "monitoring.*", "backup.*", "storage.*"]

def analisa_usuario(usuario):
    for c in range(len(usuario)):
        for i in range(len(usuarios)):
            if usuario[c] == usuarios[i]:
                return usuario[c]

def analisa_data(dia):
    for c in range(len(dia)):
        date = strftime(dia[c])
        if date != None:
            return dia[c]
            
def analisa_servico(servico):
    for c in range(len(servico)):
        for i in range(len(nome_servicos)):
            if re.search(f"{nome_servicos[i]}",servico[c]):
                print(servico[c])
                return servico[c]


# loop pega cada linha, quebra em conjunto de palavras e coloca em um dicionário
for c in range(len(logs)):
    #print(logs[c].split()) # Retorna toda linha quebrada em array, cada valor separado por espaço
    #Aplica cada conjunto ao dicionario

    newdata = {
        c : {
            "Usuario": analisa_usuario(logs[c].split()),
            "Data": analisa_data(logs[c].split()),
            "Servico": analisa_servico(logs[c].split())
        }
        }

    # Atualiza o dicionário com os novos dados
    data.update(newdata)

    # Aplica os dados ao arquivo yaml
    with open("file.yaml","w") as file:
        yaml.dump(data, file)
    print(newdata)