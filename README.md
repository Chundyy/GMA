# GMA — Gmail Malware Automation

Automatiza a triagem de emails no Gmail via IMAP, extraindo anexos e URLs e enviando-os para análise em sandbox (Cuckoo). Com base nos resultados, aplica labels no Gmail (infectado, suspeito, limpo) e gera relatórios HTML.

## Visão geral
O projeto lê emails não lidos, extrai anexos e URLs, executa análise estática e dinâmica (Cuckoo), decide uma label final e move a mensagem para a label correspondente. Há scripts de operação (menu/cron), geração de relatórios e envio automático por email.

## Fluxo de processamento
1. **IMAP**: conecta ao Gmail e lista mensagens UNSEEN.
2. **Extração**: salva anexos reais (evita inline) e detecta URLs no corpo.
3. **Análise**:
	- Estática (extensão, tamanho, double-extension, palavras suspeitas).
	- Dinâmica via Cuckoo (arquivo e/ou URL) com score.
4. **Decisão**: aplica label `INFETADOS`, `SUSPEITOS` ou `NAO_INFETADOS`.
5. **Relatório**: gera HTML com resumo e detalhes.

## Estrutura do projeto
- bin/analyze_inbox.py — pipeline principal (IMAP, extração, análise, labels).
- bin/run_job.sh — execução do job e logging.
- bin/menu.sh — menu interativo e utilitários (cron, testes, status).
- bin/self_check.sh — diagnóstico rápido do ambiente.
- bin/generate_report.sh — gera relatório HTML a partir do log.
- bin/get_report.sh — gera e envia relatório.
- bin/send_report.py — envia relatório via SMTP.
- bin/send_test_emails.sh — envia emails de teste (clean/suspect/EICAR).
- bin/cuckoo_test.py — teste simples da API do Cuckoo.
- conf/config.env.example — exemplo de configuração.
- logs/ — logs e runs.
- tmp/agent.py — agente legado do Cuckoo (código de terceiros).

## Requisitos
- Linux (scripts bash; caminhos assumem /opt/email-sandbox-automation).
- Python 3.
- Dependências CLI: `curl`, `flock`, `ip`, `awk`, `zip` (opcional), `sed`.
- Cuckoo Sandbox com API HTTP disponível.
- Conta Gmail com App Password e IMAP ativo.

## Configuração
1. Copia o exemplo para conf/config.env e ajusta:
	- Gmail/IMAP: `GMAIL_USER`, `GMAIL_APP_PASS`, `IMAP_HOST`, `IMAP_PORT`.
	- Labels: `LABEL_INFECTED`, `LABEL_SUSPECT`, `LABEL_CLEAN`.
	- Cuckoo: `CUCKOO_URL`, `CUCKOO_API_TOKEN`, `CUCKOO_API_AUTH`.
	- Paths: `BASE_DIR`, `ATTACH_DIR`.
	- Relatórios: `SEND_REPORT`, `REPORT_TO`, `SMTP_*`.
2. Garante permissões seguras em conf/config.env (600).

## Uso
- Menu interativo: executar bin/menu.sh (ou criar alias `gma`).
- Execução direta: bin/run_job.sh.
- Diagnóstico: bin/self_check.sh.
- Relatório: bin/get_report.sh.
- Testes: bin/cuckoo_test.py e bin/send_test_emails.sh.

## Modo DRY-RUN
Quando `DRY_RUN=1`, o pipeline não move mensagens; apenas simula a ação. Útil para validação inicial.

## Relatórios
O relatório HTML é gerado com base nos logs (logs/job.log) e agrupado por label. O envio por email depende de `SEND_REPORT=1` e configurações SMTP válidas.

## Segurança e privacidade
- Armazena anexos temporários em `ATTACH_DIR`.
- Recomenda-se permissões restritas em conf/config.env.
- URLs podem ser enviadas para sandbox. Ajusta `URL_ALLOWLIST_DOMAINS` se necessário.

## Limitações atuais
- Focado em Gmail (IMAP/labels).
- Dependência de Cuckoo para análise dinâmica.
- Scripts assumem Linux e caminho base fixo.

## Sugestões de melhoria
- Suporte multi-conta / multi-inbox.
- Persistência estruturada (SQLite) para relatórios e métricas.
- Integração com outras sandboxes.
- Empacotar em systemd service e deb/rpm.

## Licença
Não definida no repositório. O ficheiro tmp/agent.py contém código de terceiros (Cuckoo).
