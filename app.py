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
import numpy as np

# 환경 변수 로드
load_dotenv()

# Flask 애플리케이션 설정
app = Flask(__name__)
CORS(app)

# 로그 파일 설정
log_file_path = os.path.join(os.path.dirname(__file__), 'app.log')
log_file_path = os.path.abspath(log_file_path)


# 로그 파일 설정
file_handler = logging.FileHandler(log_file_path)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

app.logger = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)

print(f"Current log level: {logging.getLevelName(app.logger.level)}")
for handler in app.logger.handlers:
    print(f"Handler: {handler}, Level: {logging.getLevelName(handler.level)}")


# MongoDB 설정
load_dotenv(os.path.join('..', 'backend_flask', '.env'))
mongo_uri = 'mongodb+srv://ajacheol:gmomRqvRlvmV8pKe@clustersecqr.xksqi.mongodb.net/?retryWrites=true&w=majority&appName=ClusterSecQR'
db_name = 'prediction'
collection_name = 'white'

client = MongoClient(mongo_uri)
db = client[db_name]
collection = db[collection_name]

collection.create_index('url', unique=True)

# 모델 로드
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
try:
    # model = pickle.load(open('model.pkl', 'rb'))
    model = pickle.load(open(model_path, 'rb'))
    app.logger.info("Model loaded successfully")
except Exception as e:
    app.logger.error(f"Error loading model: {e}")

# BERT 모델 및 토크나이저 로드
try:
    bert_model = BertModel.from_pretrained('bert-base-uncased', output_hidden_states=True)
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    app.logger.info("BERT model and tokenizer loaded successfully")
    
except Exception as e:
    app.logger.error(f"Error loading BERT model or tokenizer: {e}")
    

# 도메인 추출 함수
def extract_domain_from_url(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:  # netloc(도메인)이 있는지 확인
        domain = parsed_url.scheme + "://" + parsed_url.netloc  # 프로토콜과 도메인을 결합하여 반환
        return domain
    else:
        return url

# URL 정보 추출 함수 (판단근거로 사용)
def get_url_info(url):
    url_info = {}

    url_info['url'] = url
    url_info['url_len'] = len(url)

    parsed_tld = tld.get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
    try:
        url_info['domain_len'] = len(parsed_tld.domain)
        url_info['tld'] = parsed_tld.tld
    except Exception as e:
        # logger.error(f"Error parsing TLD: {e}")
        app.logger.error(f"Error parsing TLD: {e}")
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
   
# URL 구성 요소 추출 함수 정의
def parse_url_components(url):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    domain = parsed_url.netloc
    path = parsed_url.path
    params = parsed_url.query
    subdomain = ".".join(parsed_url.netloc.split(".")[:-2])
    return protocol, domain, subdomain, path, params

# 각 구성 요소의 특징 추출 함수 정의
def extract_component_features(protocol, domain, subdomain, path, params):
    features = {}
    features['protocol_http'] = 1 if protocol == "http" else 0
    features['domain_len'] = len(domain)
    features['has_subdomain'] = 1 if subdomain else 0
    features['path_len'] = len(path)
    features['params_len'] = len(params)
    features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
    return features

def standardize_url(url):
    if not url.endswith('/'):
        url = url + '/'
    return url

def extract_features(url):
    url = standardize_url(url)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    inputs = tokenizer.encode_plus(url, return_tensors='pt', add_special_tokens=True, max_length=128, truncation=True)
    input_ids = inputs['input_ids']
    attention_mask = inputs.get('attention_mask', None)

    with torch.no_grad():
        outputs = bert_model(input_ids, attention_mask=attention_mask)
        hidden_states = outputs.hidden_states
        # hidden_states = outputs[2]

    token_vecs = [torch.mean(hidden_states[layer][0], dim=0) for layer in range(-4, 0)]
    # bert_features = torch.stack(token_vecs).numpy().flatten()
    bert_features = torch.stack(token_vecs).numpy()
    return bert_features

    # protocol, domain, subdomain, path, params = parse_url_components(url)
    # url_component_features = extract_component_features(protocol, domain, subdomain, path, params)
    # additional_features = np.array(list(url_component_features.values()))

    # combined_features = np.concatenate([bert_features, additional_features])
    # print(f"Combined features length: {len(combined_features)}")
    # return combined_features

def jsonify_with_objectid(data):
    if isinstance(data, dict):
        return {k: jsonify_with_objectid(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [jsonify_with_objectid(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, np.integer): 
        return int(data)
    elif isinstance(data, np.floating): 
        return float(data)
    else:
        return data
            
@app.route('/')
def home():
    prediction_api_url = os.getenv('PREDICTION_API_URL', '/predict')
    # prediction_api_url = os.getenv('PREDICTION_API_URL')
    return render_template('index.html', prediction_api_url=prediction_api_url)
    
@app.route('/predict', methods=['POST'])
def predict():
    app.logger.debug("Received POST request")
    # JSON 형식으로 받은 데이터를 파싱
    try:
        data = request.get_json(force=True)
        if not data:
            raise ValueError("No JSON data found in the request")
    except Exception as e:
        app.logger.error(f"Error parsing JSON data: {e}")
        return jsonify({'error': 'Invalid JSON format'}), 400
    
    try:
        url = data['url']
        print(f"Received URL: {url}")
        app.logger.info(f"Received URL: {url}")
    except KeyError:
        app.logger.error("Missing 'url' key in JSON data")
        return jsonify({'error': "'url' key is required"}), 400
    
    try:
        # 1. 도메인 추출
        try:
            domain_url = extract_domain_from_url(url)
            app.logger.info(f"Extracted domain URL: {domain_url}")
        except Exception as e:
            app.logger.error(f"Error extracting domain URL: {e}")
            raise
        
        # 2. DB에서 도메인 기반 비교
        try:
            url_info = collection.find_one({"url": {"$regex": f"^{domain_url}"}})
            if url_info:
                app.logger.info(f"URL found in DB with domain: {domain_url} | Type: {url_info['predicted_type']}")
            else:
                app.logger.info(f"No matching URL found in DB for domain: {domain_url}")
        except Exception as e:
            app.logger.error(f"Error finding URL in DB: {e}")
            raise
        
    
        #3. 도메인 일치하는 게 없으면 전체 URL로 BERT 수행
        if not url_info:
            try:
                url_info = get_url_info(url)
                app.logger.info(f"Extracted URL info: {url_info}")
            except Exception as e:
                app.logger.error(f"Error extracting URL info: {e}")
                raise

            try:
                features = extract_features(url)
                app.logger.info(f"Extracted features: {features}")
            except Exception as e:
                app.logger.error(f"Error extracting features: {e}")
                raise

            try:
                prediction = model.predict(features.reshape(1, -1))
                app.logger.info(f"Prediction: {prediction}")
            except Exception as e:
                app.logger.error(f"Error making prediction: {e}")
                raise

            url_info['predicted_type'] = int(prediction[0])
            try:
                collection.insert_one(url_info)
                app.logger.info(f"Inserted URL info into DB: {url_info}")
            except Exception as e:
                app.logger.error(f"Error inserting URL info into DB: {e}")
                raise
        else:
            prediction = [url_info['predicted_type']]

        # 4. 결과 반환 전 URL 정보 직렬화   
        try:
            url_info_serializable = jsonify_with_objectid(url_info)
            app.logger.info(f"URL info serializable: {url_info_serializable}")
        except Exception as e:
            app.logger.error(f"Error serializing URL info: {e}")
            raise

        return jsonify({
            'prediction': int(prediction[0]),  # numpy 정수형을 일반 int로 변환
            'url_info': url_info_serializable
        })

    except Exception as e:
        app.logger.error(f"Error during prediction: {e}")
        return jsonify({'error': 'Error during prediction'}), 500
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5500))
    app.logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)