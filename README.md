# Nerdy

Este repositório contém o projeto **Nerdy**, desenvolvido como um **projeto acadêmico**  para um sistema de **SIEM (Security Information and Event Management)** simplificado, focado na análise de logs de autenticação SSH.

## 🚀 Conceito do Projeto

O objetivo principal do Nerdy é demonstrar a capacidade de processamento e análise de logs estruturados para identificação de possíveis ameaças em um ambiente de rede. Atualmente, o sistema realiza as seguintes operações:

1.  **Ingestão de Dados**: Leitura de arquivos de log (`logs.txt`) no padrão de autenticação do serviço SSH.
2.  **Parsing de Logs**: Utilização de expressões regulares (Regex) para extrair informações críticas, como:
    *   Usuário tentado.
    *   Endereço IP de origem.
    *   Porta de conexão.
    *   PID do processo.
3.  **Classificação de Criticidade**: O sistema compara os dados extraídos com uma lista de parâmetros conhecidos (IPs e usuários confiáveis). Caso um acesso ocorra fora desses parâmetros, o evento é marcado com **Criticidade Alta**.
4.  **Exportação**: Os resultados da análise são consolidados em um arquivo estruturado `file.yaml` para posterior consumo.

## 🛠️ Melhorias para o Padrão SIEM

Embora funcional como PoC, o projeto ainda está em fase de desenvolvimento e necessita de evoluções para atingir os padrões de mercado de um SIEM completo:

*   **Ingestão em Tempo Real**: Transição de processamento em lote (batch) para processamento de fluxo (streaming) utilizando ferramentas como Logstash ou Fluentd.
*   **Armazenamento Escalável**: Substituição de arquivos YAML por bancos de dados de séries temporais ou motores de busca como Elasticsearch.
*   **Correlação de Eventos**: Implementação de regras lógicas complexas (ex: detecção de Brute Force por volume de tentativas em curto intervalo).
*   **Interface de Visualização**: Criação de dashboards para monitoramento em tempo real.
*   **Normalização de Múltiplas Fontes**: Capacidade de ler logs de diferentes serviços (Web, Firewall, Banco de Dados) além do SSH.

## 🎯 Estágio Final: Resposta Automatizada com Ansible

O estágio final deste projeto prevê a integração com o **Ansible** para fornecer uma resposta ativa a incidentes. 

A lógica de resposta será baseada na **parametrização de criticidade**:
*   **Eventos de Baixa Criticidade**: Apenas registrados para fins de auditoria.
*   **Eventos de Alta Criticidade**: Gatilho automático para Playbooks do Ansible que podem realizar ações como:
    *   Bloqueio imediato do IP de origem no Firewall (iptables/nftables).
    *   Suspensão temporária de contas de usuário suspeitas.
    *   Notificação em canais de segurança.

Esta abordagem transforma o SIEM de uma ferramenta passiva de monitoramento em uma solução ativa de defesa (SOAR - Security Orchestration, Automation, and Response).

---
*Nota: Este projeto está sendo desenvolvido na branch `dev` para testes de novas funcionalidades de parsing e integração.*
