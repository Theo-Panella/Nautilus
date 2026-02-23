# --------------------------------------------------------
# Pega os dados de logs e os organiza em um arquivo yaml
# --------------------------------------------------------


import yaml

file = open('logs.txt', 'r')
data = {}
logs = file.readlines() #Pega o dia (primeiro valor do log) e coloca o resultado na array logs array


# loop pega cada linha, quebra em conjunto de palavras e coloca em um dicionário
for c in range(len(logs)):
    #print(logs[c].split()) # Retorna toda linha quebrada em array, cada valor separado por espaço
    #Aplica cada conjunto ao dicionario
    newdata = {
        c : logs[c].split()
        }

    # Atualiza o dicionário com os novos dados
    data.update(newdata)

    # Aplica os dados ao arquivo yaml
    with open("file.yaml","w") as file:
        yaml.dump(data, file)