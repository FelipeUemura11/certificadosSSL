import ssl
import socket
import csv
from OpenSSL import crypto
from datetime import datetime, timezone
import re
import os

def verificaValidadeSSL(dominio):
    try:
        cert_pem = ssl.get_server_certificate((dominio, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        not_after_bytes = x509.get_notAfter()
        not_after_str = not_after_bytes.decode('ascii')
        data_expiracao = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')
        data_expiracao_utc = data_expiracao.replace(tzinfo=timezone.utc) # Corrigido erro de digitação aqui
        agora_utc = datetime.now(timezone.utc)
        dias_restantes = (data_expiracao_utc - agora_utc).days
        subject = x509.get_subject()
        common_name = None
        for component in subject.get_components():
            if component[0] == b'CN':
                common_name = component[1].decode('utf-8')
                break

        if common_name and common_name.endswith('.com.br'):
            common_name = common_name.removesuffix('.com.br')

        return {
            "dominio": dominio,
            "common_name_certificado": common_name,
            "data_expiracao": data_expiracao,
            "dias_restantes": dias_restantes
        }
    except ssl.SSLError as e:
        print(f"Erro SSL para {dominio}: {e}")
        return None
    except socket.gaierror:
        print(f"Erro: Não foi possível resolver o domínio '{dominio}'. Verifique se ele está correto.")
        return None
    except ConnectionRefusedError:
        print(f"Erro: Não foi possível conectar ao domínio '{dominio}'. Verifique se ele está correto e acessível.")
        return None
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao verificar {dominio}: {e}")
        return None

def processar_dominios_csv(arquivo_csv):
    dominios_expirados = []
    dominios_validos = []
    dominios_erro = []

    try:
        with open(arquivo_csv, 'r', encoding='utf-8') as arquivo:
            leitor = csv.DictReader(arquivo)
            
            print(f"Colunas detectadas pelo csv.DictReader: {leitor.fieldnames}")

            if 'id' not in leitor.fieldnames or 'dominio' not in leitor.fieldnames:
                print(f"Erro: As colunas 'id' e 'dominio' não foram encontradas no CSV.")
                print(f"Por favor, verifique se o arquivo '{arquivo_csv}' tem o cabeçalho correto e o delimitador de vírgula.")
                print(f"Colunas detectadas: {leitor.fieldnames}") 
                return None, None, None

            for linha in leitor:
                dominio_id = linha['id'].strip()
                
                dominio_original = linha['dominio'].strip()
                dominio = re.sub(r'https?://', '', dominio_original)
                dominio = dominio.rstrip('/')
                
                print(f"Processando ID: {dominio_id}, Domínio: {dominio_original} (limpo para: {dominio})")

                info_certificado = verificaValidadeSSL(dominio)

                if info_certificado:
                    resultado = {
                        'id': dominio_id,
                        'dominio_original_csv': dominio_original,
                        'dominio_verificado': dominio,
                        'common_name': info_certificado['common_name_certificado'],
                        'data_expiracao': info_certificado['data_expiracao'],
                        'dias_restantes': info_certificado['dias_restantes']
                    }
                    if info_certificado['dias_restantes'] <= 0:
                        dominios_expirados.append(resultado)
                    else:
                        dominios_validos.append(resultado)
                else:
                    dominios_erro.append({
                        'id': dominio_id,
                        'dominio_original_csv': dominio_original,
                        'dominio_tentado_verificar': dominio,
                        'erro': 'Não foi possível verificar o certificado'
                    })

        return dominios_expirados, dominios_validos, dominios_erro
    except FileNotFoundError:
        print(f"Erro: O arquivo {arquivo_csv} não foi encontrado.")
        return None, None, None
    except Exception as e:
        print(f"Erro ao processar o arquivo CSV: {e}")
        return None, None, None

def salvar_resultados(dominios_expirados, dominios_validos, dominios_erro, output_dir='relatorios_ssl'):

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Diretório '{output_dir}' criado para salvar os relatórios.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_expirados_path = os.path.join(output_dir, f'dominios_expirados_{timestamp}.csv')
    with open(output_expirados_path, 'w', newline='', encoding='utf-8') as arquivo:
        campos = ['id', 'dominio_original_csv', 'dominio_verificado', 'common_name', 'data_expiracao', 'dias_restantes']
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for dominio in dominios_expirados:
            if isinstance(dominio.get('data_expiracao'), datetime):
                dominio['data_expiracao'] = dominio['data_expiracao'].strftime('%d/%m/%Y %H:%M:%S UTC')
            else:
                dominio['data_expiracao'] = 'N/A'
            escritor.writerow(dominio)
    print(f"- {output_expirados_path}")

    output_validos_path = os.path.join(output_dir, f'dominios_validos_{timestamp}.csv')
    with open(output_validos_path, 'w', newline='', encoding='utf-8') as arquivo:
        campos = ['id', 'dominio_original_csv', 'dominio_verificado', 'common_name', 'data_expiracao', 'dias_restantes']
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for dominio in dominios_validos:
            if isinstance(dominio.get('data_expiracao'), datetime):
                dominio['data_expiracao'] = dominio['data_expiracao'].strftime('%d/%m/%Y %H:%M:%S UTC')
            else:
                dominio['data_expiracao'] = 'N/A'
            escritor.writerow(dominio)
    print(f"- {output_validos_path}")
    
    output_erro_path = os.path.join(output_dir, f'dominios_erro_{timestamp}.csv')
    with open(output_erro_path, 'w', newline='', encoding='utf-8') as arquivo:
        campos = ['id', 'dominio_original_csv', 'dominio_tentado_verificar', 'erro']
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        escritor.writerows(dominios_erro)
    print(f"- {output_erro_path}")

if __name__ == "__main__":
    print(" >> Verificador de Certificados SSL em Lote <<")
    
    arquivo_csv = input("Digite o nome do arquivo CSV (ex: data/domains.csv): ").strip()
    
    if arquivo_csv:
        print("\nProcessando domínios...")
        dominios_expirados, dominios_validos, dominios_erro = processar_dominios_csv(arquivo_csv)
        
        if dominios_expirados is not None:
            print("\n>> Resultados da Verificação <<")
            print(f"Total de domínios expirados: {len(dominios_expirados)}")
            print(f"Total de domínios válidos: {len(dominios_validos)}")
            print(f"Total de domínios com erro: {len(dominios_erro)}")
            
            salvar_resultados(dominios_expirados, dominios_validos, dominios_erro, output_dir='relatorios_ssl')
            print("\nResultados salvos no diretório 'relatorios_ssl'.")