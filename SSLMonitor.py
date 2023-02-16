# Author: Igor Andrade
# Debian-PB.org
#
#
import ssl
import socket
import datetime
import json
import requests

# Dominios, coloque aqui
domains_file = '/root/SSL_Monitor/domains.txt'

# Microsoft Teams webhook URL aqui
teams_webhook = 'YOURURLHERE'

# Dias para acabar o SSL
alert_days = 30

def get_cert_expiration_date(hostname):
    """
    Retorna a data de expiracao do certificado
    """
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
    conn.connect((hostname, 443))
    cert = conn.getpeercert()
    conn.close()
    return datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

def send_alert_to_teams(domain, days_left):
    """
    manda alerta para o teams sala desejada do webhook
    """
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.0",
        "body": [
            {
                "type": "Container",
                "items": [
                    {
                        "type": "Image",
                        "url": "https://www.hardware.com.br/static/wp/2022/07/06/blog_15418_large.jpg",
                        "size": "auto"
                    }
                ]
            },
            {
                "type": "TextBlock",
                "text": "SSL Certificates Monitoring",
                "weight": "bolder",
                "size": "medium"
            },
            {
                "type": "TextBlock",
                "text": f"Dominio: {domain}"
            },
            {
                "type": "TextBlock",
                "text": f"SSL vence em: {days_left} days"
            },
            {
                "type": "TextBlock",
                "text": datetime.datetime.now().strftime("Data desse alerta: %d-%m-%Y")
            }
        ],
        "actions": [
            {
                "type": "Action.OpenUrl",
                "title": "Domains that are being checked",
                "url": "URLTOALIST-TEXT-OR-GRAFANA-DASHBOARD"
            }
        ]
    }

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card
            }
        ]
    }
    response = requests.post(teams_webhook, json=payload)
    if response.status_code != 200:
        print(f'Failed to send alert to Microsoft Teams: {response.text}')

# lê os dominios dentro de domains.txt
with open(domains_file, 'r') as f:
    domains = [line.strip() for line in f.readlines()]

# valida a data de expiração em formato de dias restantes para expirar, explode no STDOUT e manda pro teams via webhook
for domain in domains:
    try:
        expiration_date = get_cert_expiration_date(domain)
        days_left = (expiration_date - datetime.datetime.now()).days
        print(f'{domain}: {days_left} days left')
        if days_left < alert_days:
            send_alert_to_teams(domain, days_left)
    except Exception as e:
        print(f'Failed to check SSL certificate for {domain}: {e}')
