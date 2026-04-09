from flask import Blueprint, render_template, request, jsonify
import requests
import json
from flaskr.config import CCIPS_API

view_bp = Blueprint('view', __name__, url_prefix='/view')


def _ccips_all_url():
    if CCIPS_API.endswith('/ccips'):
        return CCIPS_API[:-len('/ccips')] + '/ccips-all'
    if CCIPS_API.endswith('/ccips/'):
        return CCIPS_API[:-len('/ccips/')] + '/ccips-all'
    return f"{CCIPS_API.rstrip('/')}-all"


@view_bp.route('/ccips-all')
def get_ccips_all():
    try:
        response = requests.get(_ccips_all_url())
        if response.status_code == 200:
            data = response.json()
            return jsonify(data)
        else:
            return jsonify({"error": f"API error: {response.status}"}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@view_bp.route('/', methods=['GET', 'POST'])
def view_home():
    tunnel_data = None
    error = None

    if request.method == 'POST':
        tunnel_id = request.form.get('data_id')
        try:
            if tunnel_id == '':
                error = "Introduce una opción válida para visualizar"
            else:
                response = requests.get(f"{CCIPS_API}/{tunnel_id}")
                if response.status_code == 200:
                    tunnel_data = response.json()
                    print("API Response:", json.dumps(tunnel_data, indent=2))#SOLO UTIL PARA DEBUG
                else:
                    error = f"Tunnel not found or error: {response.text}"
        except Exception as e:
            error = f"Error contacting API: {str(e)}"

    return render_template('view.html', title="View Data", tunnel=tunnel_data, error=error)
