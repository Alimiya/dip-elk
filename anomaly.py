import requests
import pandas as pd
import numpy as np
import re
from requests.auth import HTTPBasicAuth
from sklearn.ensemble import IsolationForest

#  Настройки подключения к Elasticsearch
ELASTIC_URL = "http://localhost:9200/filebeat-*/_search"
ELASTIC_USER = "elastic"
ELASTIC_PASS = "changeme"

#  Запрос логов (исключаем INFO, WARN)
query = {
    "_source": ["@timestamp", "message"],
    "query": {
        "bool": {
            "must_not": [
                {"match": {"message": "INFO"}},
                {"match": {"message": "WARN"}}
            ]
        }
    },
    "size": 100,
    "sort": [{"@timestamp": "desc"}]
}

response = requests.get(ELASTIC_URL, auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS), json=query)

if response.status_code == 200:
    logs = response.json()["hits"]["hits"]
else:
    print("Ошибка получения логов:", response.text)
    exit()

#  Преобразуем логи в DataFrame
df = pd.DataFrame([log["_source"] for log in logs])

#  Проверяем, есть ли нужные столбцы
if "@timestamp" not in df.columns or "message" not in df.columns:
    print("Ошибка: нет данных в логах!")
    exit()

#  Преобразуем timestamp в число (UNIX-время)
df["timestamp"] = pd.to_datetime(df["@timestamp"]).astype(int) / 10**9

#  Извлечение имени пользователя из ошибок входа
def extract_username(msg):
    match = re.search(r"unable to authenticate user \[(.*?)\]", msg)
    return match.group(1) if match else None

df["user"] = df["message"].apply(extract_username)

#  Фильтрация логов с ошибками входа
login_errors = df[df["message"].str.contains("Login attempt failed", na=False, case=False)]

#  Кодируем текст сообщений
df["message_len"] = df["message"].apply(len)

#  Выбираем только числовые признаки для модели
features = df[["timestamp", "message_len"]]

#  Обучаем модель Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)
df["anomaly"] = model.fit_predict(features)

#  Выводим аномальные логи
anomalies = df[df["anomaly"] == -1]

#  Итоговый вывод
print("\n Ошибки входа:")
print(login_errors[["@timestamp", "message", "user"]])

print("\n Найдены аномальные логи:")
print(anomalies[["@timestamp", "message"]])