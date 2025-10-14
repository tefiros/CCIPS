from flask import Blueprint, render_template, request, jsonify
import requests #to send HTTP requests to the external API
from flaskr.config import CCIPS_API #CCIPS APi adress
import json 


create_bp = Blueprint('create', __name__)

# Route to render the HTML page for tunnel creation
@create_bp.route('/')
def create_home():
    return render_template('create.html', title="Create Data")

# Route that handles tunnel creation logic (triggered via POST from JavaScript)
@create_bp.route('/create_tunnel', methods=['POST'])
def create_tunnel():
    data = request.json  # Stores the JSON data sent from the frontend
    
    # Construct the 'nodes' array for both tunnel endpoints
    nodes= [
        {"ipData": data["node1_ip_data"],
         "ipControl": data["node1_ip_control"]},
                
        {"ipData": data["node2_ip_data"],
         "ipControl": data["node2_ip_control"]}
        ]
    #for function mode G2G considers network internal paramenters
    if data.get("node1_dmz"):
        nodes[0]["ipDMZ"] = data["node1_dmz"]
    if data.get("node1_network"):
        nodes[0]["networkInternal"] = data["node1_network"]
    
    if data.get("node2_dmz"):
        nodes[1]["ipDMZ"] = data["node2_dmz"]
    if data.get("node2_network"):
        nodes[1]["networkInternal"] = data["node2_network"]
    
    # Build the final JSON payload with all the parameters to be sent to the API
    payload = {
        "nodes": nodes,        
        "encAlg": [data["encAlg"]],
        "intAlg": [data["intAlg"]],
        "softLifetime": {"nTime": int(data["softLifetime"])},
        "hardLifetime": {"nTime": int(data["hardLifetime"])}
        }

    #print("Payload a enviar:", payload)#SOLO UTIL PARA DEBUG
    print("Submitted Payload:", json.dumps(payload, indent=2))#SOLO UTIL PARA DEBUG

    
    # Send request to CCIPS API
    try:
        response = requests.post(CCIPS_API, json=payload) #POST requset to API of the JSON
        return jsonify(response.json()), response.status_code #Return the API response
    except Exception as e:
        return jsonify({"error": f"Connection to API failed: {str(e)}"}), 500

