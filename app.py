from flask import Flask, render_template, jsonify
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

# Your API key
api_key = 'e9285471-b05b-4b8e-a63e-3f1e41ee4d9f'

# Base URLs for the APIs
cpe_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
cve_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
headers = {'apiKey': api_key}

# Function to fetch CVEs for each CPE
def fetch_cves_for_cpe(cpe_name):
    params_cve = {
        'cpeName': cpe_name,
        'resultsPerPage': 5,
    }
    response_cve = requests.get(cve_url, headers=headers, params=params_cve)
    if response_cve.status_code == 200:
        cve_data = response_cve.json()
        return cve_data.get('vulnerabilities', [])
    else:
        return []

# Route to display the CPE and CVE data
@app.route('/')
def index():
    end_date = datetime.now()
    start_date = end_date - timedelta(days=120)

    start_date_iso = start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    end_date_iso = end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    # Parameters for fetching CPEs (Microsoft products within the date range)
    params_cpe = {
        'cpeMatchString': 'cpe:2.3:*:Microsoft',
        'lastModStartDate': start_date_iso,
        'lastModEndDate': end_date_iso,
        'resultsPerPage': 20,
        'startIndex': 0
    }

    # Fetch CPE records
    response_cpe = requests.get(cpe_url, headers=headers, params=params_cpe)

    if response_cpe.status_code == 200:
        data = response_cpe.json()
        cpe_data = []
        
        for product in data.get('products', []):
            if not product['cpe'].get('deprecated', False):  # Only include non-deprecated products
                cpe_name = product['cpe'].get('cpeName', 'N/A')
                title = product['cpe']['titles'][0].get('title', 'N/A')
                last_modified = product['cpe'].get('lastModified', 'N/A')

                # Fetch corresponding CVEs for this CPE
                cve_items = fetch_cves_for_cpe(cpe_name)
                cves = [{'id': cve.get('cve', {}).get('id', 'N/A'), 
                         'description': cve.get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description available')} 
                        for cve in cve_items]

                cpe_data.append({
                    'cpe_name': cpe_name,
                    'title': title,
                    'last_modified': last_modified,
                    'cves': cves
                })

        return render_template('index.html', cpe_data=cpe_data)
    else:
        return 'Failed to retrieve data', 500


if __name__ == '__main__':
    app.run(debug=True, port=5001)
