import sys
import time
import whois
import ssl
import numpy as np
import urllib.request
import requests
import socket
import re
import urllib.parse
import datetime
import hashlib
import pandas as pd
import pickle
import joblib
import concurrent.futures
from tld import get_tld
from urllib.request import urlopen
from bs4 import BeautifulSoup
from datetime import datetime
from dateutil.parser import parse
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from flask import Flask
from flask import request
from flask import json
from flask import jsonify
import functions.features as features

app = Flask(__name__)


@app.route('/get-result', methods=['POST'])
def index():
    # retrieve message as json, should contain a payload
    inMessage = json.loads(request.get_data().decode('utf-8'))
    payload = inMessage[u'payload']
    # assign score to documents in the payload
    prediction = predict(payload)
    return jsonify(
        result=prediction['result']
    )


@app.route('/get-result/details', methods=['POST'])
def predict_with_details():
    inMessage = json.loads(request.get_data().decode('utf-8'))
    payload = inMessage[u'payload']
    # assign score to documents in the payload
    prediction = predict(payload)
    return jsonify(
        result=prediction['result'],
        details=prediction['details']
    )


def predict(url):
    start = time.perf_counter()
    check_fish = pd.DataFrame(columns=['check_IP_Address', 'check_URL_Length', '@',
                              'check -', 'sub_domain', 'SSL', 'domain_regi', '//', 'port_scan', 'web_traffic'])
    ch_ip = features.check_IP_Address(url)
    ch_len = features.check_URL_Length(url)
    ch_at = features.check_AT_Symbol(url)
    ch_hy = features.check_Hyphen(url)
    ch_sub = features.check_Sub_Domain(url)
    ch_ssl = features.check_SSL(url)
    ch_peri = features.check_Domain_registration_period(url)
    ch_slash = features.check_double_slash(url)
    ch_port = features.check_port_scan(url)
    ch_traffic = features.check_web_traffic(url, alexalist)
    check_fish = check_fish.append(pd.DataFrame([[ch_ip, ch_len, ch_at, ch_hy, ch_sub, ch_ssl, ch_peri, ch_slash, ch_port, ch_traffic]], columns=[
        'check_IP_Address', 'check_URL_Length', '@', 'check -', 'sub_domain', 'SSL', 'domain_regi', '//', 'port_scan', 'web_traffic']), ignore_index=True)
    end = time.perf_counter()

    print(f"정보 가져오는데 드는 시간... {round(end - start, 2)}초.....")
    pred = clf.predict(check_fish)
    if -1 in pred:
        return {
            "result": "phishing",
            "details": {
                "ch_ip": ch_ip,
                "ch_len": ch_len,
                "ch_at": ch_at,
                "ch_hy": ch_hy,
                "ch_sub": ch_sub,
                "ch_ssl": ch_ssl,
                "ch_peri": ch_peri,
                "ch_slash": ch_slash,
                "ch_port": ch_port,
                "ch_traffic": ch_traffic
            }
        }
        # return json.dumps({"result": "phishing"})
    else:
        return {
            "result": "ok",
            "details": {
                "ch_ip": ch_ip,
                "ch_len": ch_len,
                "ch_at": ch_at,
                "ch_hy": ch_hy,
                "ch_sub": ch_sub,
                "ch_ssl": ch_ssl,
                "ch_peri": ch_peri,
                "ch_slash": ch_slash,
                "ch_port": ch_port,
                "ch_traffic": ch_traffic
            }
        }


if __name__ == "__main__":
    global alexadata, alexalist
    alexadata = np.genfromtxt("majestic_million.csv",
                              delimiter=',', dtype="|U")
    alexalist = alexadata[0:1000000, 2]
    clf = joblib.load("clf_forest.pkl")
    app.run()
    ###### 모델 저장 시작.. ######
    # training_data = np.genfromtxt(
    #     'ALEXA_traffic_add_merged_shuffled_fix.csv', delimiter=',', dtype=np.int32)

    # inputs = training_data[:, :-1]
    # outputs = training_data[:, -1]
    # training_inputs = inputs[:2150]
    # training_outputs = outputs[:2150]
    # testing_inputs = inputs[2150:]
    # testing_outputs = outputs[2150:]

    # clf_forest = RandomForestClassifier(random_state=42)
    # clf_forest.fit(inputs, outputs)

    # saved_model = pickle.dumps(clf_forest)

    # joblib.dump(clf_forest, 'clf_forest.pkl')
    ###### 모델 저장 끝 ######

    # 모델 불러오기
    # start = time.perf_counter()

    # clf_forest = joblib.load("clf_forest.pkl")
    # check_fish = pd.DataFrame(columns=['check_IP_Address', 'check_URL_Length', '@',
    #                           'check -', 'sub_domain', 'SSL', 'domain_regi', '//', 'port_scan', 'web_traffic'])

    # url = 'http://c11.kr'
    # ch_ip = check_IP_Address(url)
    # ch_len = check_URL_Length(url)
    # ch_at = check_AT_Symbol(url)
    # ch_hy = check_Hyphen(url)
    # ch_sub = check_Sub_Domain(url)
    # ch_ssl = check_SSL(url)
    # ch_peri = check_Domain_registration_period(url)
    # ch_slash = check_double_slash(url)
    # ch_port = check_port_scan(url)
    # ch_traffic = check_web_traffic(url)

    # check_fish = check_fish.append(pd.DataFrame([[ch_ip, ch_len, ch_at, ch_hy, ch_sub, ch_ssl, ch_peri, ch_slash, ch_port, ch_traffic]], columns=[
    #                                'check_IP_Address', 'check_URL_Length', '@', 'check -', 'sub_domain', 'SSL', 'domain_regi', '//', 'port_scan', 'web_traffic']), ignore_index=True)

    # pred = clf_forest.predict(check_fish)

    # end = time.perf_counter()
    # if -1 in pred:
    #     print("피싱사이트")
    # else:
    #     print("정상사이트")

    # print(f"수행까지 {round(end - start, 2)}초 걸렸음.")
