import re
from datetime import *
from time import strftime
import yaml


# Padrão de Analise
# Data | Hora | IP de requisicao | IP de Destino | Serviço | Porta | Protocolo | Username | Hostname
# Tipo de log: Erro, acesso, alteração, requisição

data_atual = date.today()
usuarios = ["root", "admin", "theo", "serginho", "roberto", "maria", "joao", "pedro", "lucas", "ana"]
data = {}
file = open('logs.txt', 'r')
logs = file.readlines() #Pega linha por linha 


def analisa_data(dia):
    for c in range(len(dia)):
        if dia[c] == strftime("%Y-%m-%d"):
            return dia[c]

def analisa_usuario(usuario):
    for c in range(len(usuario)):
        for i in range(len(usuarios)):
            if usuario[c] == usuarios[i]:
                return usuario[c]

def analisa(log_splitado):
    newdata = {
        "Data do Log": analisa_data(log_splitado),
        "Usuario do Log": analisa_usuario(log_splitado)
        }
    
    # Atualiza o dicionário com os novos dados
    newdata.update(data)

    # Aplica os dados ao arquivo yaml
    with open("file.yaml","w") as yaml_file:
        yaml.dump(newdata, yaml_file)
    print(data)
    print(newdata)


    #if analisa_usuario(log_splitado) == None:
    #    print("Usuario do Log: Usuario não encontrado")
    #else:
    #    print(f"Usuario do Log: {analisa_usuario(log_splitado)}")
    #print(f"Data do Log: {analisa_data(log_splitado)}")
    #print(" ")


#file = open('logs.txt', 'r')
#logs = re.findall(f"{data_atual}.+",file.read()) #Pega o dia (primeiro valor do log) e coloca o resultado na array logs array

for c in range(len(logs)):
    analisa(logs[c].split()) # Retorna toda linha quebrada em array, cada valor separado por espaço

