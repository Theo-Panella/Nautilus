import re

# Padrão de Analise
# Data | Hora | serviço | Tipo de log
# Tipo de log: Erro, acesso, alteração, requisição
file = open('logs.txt', 'r')
default_words = ['sshd','nginx','node-app','mysqld','kernel','docker','CRON','systemd']


search_Acess_in_file = re.findall("Acce.+",file.read()) #Coloca o resultado em array
print(search_Acess_in_file)

for i in range(len(search_Acess_in_file)):
    print(i)
    for c in range(len(default_words)):
        print(c)
        search_default_words = re.search(f'sshd.+',search_Acess_in_file[i])
    print(search_default_words)