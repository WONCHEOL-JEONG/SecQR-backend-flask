from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient
from urllib.parse import urlparse
import re
import tld
import dns.resolver
from bson import ObjectId
from transformers import BertTokenizer, BertModel
import torch
import pickle
from dotenv import load_dotenv
import os
import logging

# 환경 변수 로드
load_dotenv()

# Flask 애플리케이션 설정
app = Flask(__name__)
CORS(app)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB 설정
mongo_uri = 'mongodb+srv://ajacheol:gmomRqvRlvmV8pKe@clustersecqr.xksqi.mongodb.net/?retryWrites=true&w=majority&appName=ClusterSecQR'
db_name = 'prediction'
collection_name = 'white'

client = MongoClient(mongo_uri)
db = client[db_name]
collection = db[collection_name]

collection.create_index('url', unique=True)

# 모델 로드
try:
    model = pickle.load(open('model.pkl', 'rb'))
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {e}")

# BERT 모델 및 토크나이저 로드
try:
    bert_model = BertModel.from_pretrained('bert-base-uncased', output_hidden_states=True)
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    logger.info("BERT model and tokenizer loaded successfully")
except Exception as e:
    logger.error(f"Error loading BERT model or tokenizer: {e}")

def get_url_info(url):
    url_info = {}

    url_info['url'] = url
    url_info['url_len'] = len(url)

    parsed_tld = tld.get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
    try:
        url_info['domain_len'] = len(parsed_tld.domain)
        url_info['tld'] = parsed_tld.tld
    except Exception as e:
        logger.error(f"Error parsing TLD: {e}")
        url_info['domain_len'] = 0
        url_info['tld'] = ""

    def having_Sub_Domain(parsed_tld):
        if parsed_tld is not None:
            subdomain = parsed_tld.subdomain
            if subdomain == "":
                return 0
            return 1
        return 0
    url_info['sub_domain'] = having_Sub_Domain(parsed_tld)

    parsed_url = urlparse(url)
    url_info['parameter_len'] = len(parsed_url.query)

    ipv4_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ipv6_pattern = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,7}:|'
                              r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                              r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                              r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                              r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                              r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                              r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
                              r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
                              r'::(ffff(:0{1,4}){0,1}:){0,1}'
                              r'(([0-9]{1,3}\.){3,3}[0-9]{1,3})|'
                              r'([0-9a-fA-F]{1,4}:){1,4}'
                              r':([0-9]{1,3}\.){3,3}[0-9]{1,3})')
    url_info['having_ip_address'] = 1 if ipv4_pattern.search(url) or ipv6_pattern.search(url) else 0

    url_info['protocol'] = 1 if urlparse(url).scheme == "http" else 0

    hostname = parsed_url.hostname
    url_info['abnormal_url'] = 0
    if hostname:
        try:
            dns.resolver.resolve(hostname, 'A')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            url_info['abnormal_url'] = 1
        except Exception as e:
            url_info['abnormal_url'] = 1

    return url_info

def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    inputs = tokenizer.encode_plus(url, return_tensors='pt', add_special_tokens=True, max_length=512, truncation=True)
    input_ids = inputs['input_ids']

    attention_mask = inputs.get('attention_mask')

    with torch.no_grad():
        outputs = bert_model(input_ids, attention_mask=attention_mask)
        hidden_states = outputs[2]

    token_vecs = [torch.mean(hidden_states[layer][0], dim=0) for layer in range(-4, 0)]
    return torch.stack(token_vecs).numpy()

def jsonify_with_objectid(data):
    if isinstance(data, dict):
        return {k: jsonify_with_objectid(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [jsonify_with_objectid(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data

@app.route('/')
def home():
    prediction_api_url = os.getenv('PREDICTION_API_URL')
    return render_template('index.html', prediction_api_url=prediction_api_url)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    app.logger.info(f"Received URL: {url}")

    try:
        url_info = collection.find_one({"url": url})
        app.logger.info(f"URL info from DB: {url_info}")

        if not url_info:
            url_info = get_url_info(url)
            app.logger.info(f"Extracted URL info: {url_info}")

            features = extract_features(url)
            app.logger.info(f"Extracted features: {features}")

            prediction = model.predict(features.reshape(1, -1))
            app.logger.info(f"Prediction: {prediction}")

            url_info['predicted_type'] = prediction[0]
            try:
                collection.insert_one(url_info)
            except Exception as e:
                app.logger.error(f"Error inserting URL info into DB: {e}")
        else:
            prediction = [url_info['predicted_type']]

        url_info_serializable = jsonify_with_objectid(url_info)
        app.logger.info(f"URL info serializable: {url_info_serializable}")

        return jsonify({
            'prediction': prediction[0],
            'url_info': url_info_serializable
        })

    except Exception as e:
        app.logger.error(f"Error during prediction: {e}")
        return jsonify({'error': 'Error during prediction'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
