# Verificador de Certificados SSL em Lote

Este projeto realiza a verificação em lote da validade de certificados SSL de uma lista de domínios informada em um arquivo CSV. Ele gera relatórios em CSV com os domínios válidos, expirados e com erro de verificação.

## Como funciona

O script [`main.py`](main.py) lê um arquivo CSV contendo domínios, verifica a validade do certificado SSL de cada domínio e salva os resultados em arquivos separados na pasta `relatorios_ssl/`.

### Entrada

O arquivo de entrada deve estar no formato CSV, com as colunas:

- `id`: identificador único do domínio
- `dominio`: domínio a ser verificado (pode conter http/https)

Exemplo ([data/domains.csv](data/domains.csv)):

### Saída

Os relatórios são gerados na pasta `relatorios_ssl/`:

- `dominios_validos_<timestamp>.csv`: domínios com certificado válido
- `dominios_expirados_<timestamp>.csv`: domínios com certificado expirado
- `dominios_erro_<timestamp>.csv`: domínios que não puderam ser verificados
