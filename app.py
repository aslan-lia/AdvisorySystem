from flask import Flask, render_template, request, jsonify
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

# Your API key
api_key = 'e9285471-b05b-4b8e-a63e-3f1e41ee4d9f'

# Base URLs for the APIs
cpe_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
cve_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
headers = {'apiKey': api_key}

def fetch_cves_for_cpe(cpe_name):
    params_cve = {
        'cpeName': cpe_name,
        'resultsPerPage': 20,
    }
    response_cve = requests.get(cve_url, headers=headers, params=params_cve)
    if response_cve.status_code == 200:
        cve_data = response_cve.json()
        return cve_data.get('vulnerabilities', [])
    else:
        return []

def generate_date_ranges(start_date, end_date):
    start = datetime.strptime(start_date, '%Y-%m-%d')
    end = datetime.strptime(end_date, '%Y-%m-%d')
    ranges = []

    while start < end:
        next_end = min(start + timedelta(days=120), end)
        ranges.append((start.strftime('%Y-%m-%dT%H:%M:%S.000Z'), next_end.strftime('%Y-%m-%dT%H:%M:%S.000Z')))
        start = next_end + timedelta(days=1)

    return ranges

def fetch_all_cpe_data(start_date, end_date, params_cpe):
    all_cpe_data = []
    date_ranges = generate_date_ranges(start_date, end_date)

    for start_iso, end_iso in date_ranges:
        params_cpe['lastModStartDate'] = start_iso
        params_cpe['lastModEndDate'] = end_iso

        start_index = 0
        while True:
            params_cpe['startIndex'] = start_index
            response_cpe = requests.get(cpe_url, headers=headers, params=params_cpe)

            if response_cpe.status_code == 200:
                data = response_cpe.json()
                products = data.get('products', [])
                all_cpe_data.extend(products)

                start_index += len(products)

                if len(products) < params_cpe['resultsPerPage']:
                    break
            else:
                break

    return all_cpe_data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    data = request.json
    cpe_match = data.get('cpe_match', '').strip()
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    if not cpe_match or not start_date or not end_date:
        return jsonify({'error': 'Please provide all the required fields.'}), 400

    params_cpe = {
        'cpeMatchString': cpe_match,
        'resultsPerPage': 10000,
    }

    cpe_data = fetch_all_cpe_data(start_date, end_date, params_cpe)

    processed_cpe_data = []
    for product in cpe_data:
        if not product['cpe'].get('deprecated', False):
            cpe_name = product['cpe'].get('cpeName', 'N/A')
            title = product['cpe']['titles'][0].get('title', 'N/A')
            last_modified = product['cpe'].get('lastModified', 'N/A')

            cve_items = fetch_cves_for_cpe(cpe_name)
            cves = [{'id': cve.get('cve', {}).get('id', 'N/A'), 
                     'description': cve.get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description available')} 
                    for cve in cve_items]

            processed_cpe_data.append({
                'cpe_name': cpe_name,
                'title': title,
                'last_modified': last_modified,
                'cves': cves
            })

    return jsonify({'cpe_data': processed_cpe_data})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
