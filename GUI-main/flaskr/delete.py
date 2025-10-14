from flask import Blueprint, render_template, request
import requests
from flaskr.config import CCIPS_API

delete_bp = Blueprint('delete', __name__, url_prefix='/delete')

@delete_bp.route('/', methods=['GET', 'POST'])

def delete_home():
    message = None
    error = None

    if request.method == 'POST':
        tunnel_id = request.form.get('delete_id')
        try:
            if tunnel_id == '':
                error = "Introduce a tunnel ID to delete"
            else:
                response = requests.delete(f"{CCIPS_API}/{tunnel_id}")
                if response.status_code == 200:
                    message = f"Tunnel {tunnel_id} deleted successfully."
                else:
                    error = f"Failed to delete tunnel: {response.text}"
        except Exception as e:
            error = f"Error contacting API: {str(e)}"

    return render_template('delete.html', title="Delete Tunnel", message=message, error=error)