<!-- # © 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. -->
# 🌐 CCIPS Web GUI

Management and handling system developed with **Python Flask** to facilitate the use of the CCIPS controller.

This system provides the project with a graphical user interface that manages the external CCIPS controller API and enables the use of all its functionalities.

Through this interface, users can easily **create**, **view**, and **delete** tunnels directly from the browser, while also displaying a simple graphical representation of the network topology.

---

## 📂 Project Structure

```
flask/
├── init.py     # Initializes the app and registers blueprints
├── config.py   # CCIPS API controller address
├── create.py   # Logic for tunnel creation
├── delete.py   # Logic for tunnel deletion
├── view.py     # Logic for tunnel visualization
├── templates/
│ ├── base.html     # Base layout template
│ ├── create.html   # Tunnel creation form
│ ├── delete.html   # Tunnel deletion form
│ └── view.html     # Tunnel visualization and topology
└── static/
│ ├── style.css   # Custom styles
```

## :open_book: Project Guide

Check this simple guide for general info about the project code files.

https://hackmd.io/@3f15EmG2QJ2UFNbDpGVjxg/BJYG7gCeeg

---

## ⚙️ Configuration

The file `config.py` contains the adress where the CCIPS controller is running.
```python
CCIPS_API = "http://localhost:5000/ccips"
```

If this project runs in the same machine where the CCIPS controller is running no changes are needed as its configured for localhost:5000.

If CCIPS controller is running in a different place  make sure to update this file with the right adress and ensure conectivity between both CCIPS_controller and GUI hosts.

---

## 🚀 Installation & Execution

### 1. Install Python 3 and required tools

```bash
sudo apt-get install -y python3 python3-venv python3-pip
```

### 2. Clone the repository

```bash
cd GUI
```

### 3. Create and activate a Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install requiered packages on the virtual environmnet

```bash
pip install flask
pip install flask requests
```

### 5. Run the project

```bash
flask --app flaskr run --host=host_IP_adress --port=Desired_port
```
---

## ✍️ Authors

Pablo Martinez Seco de Herrera.
Mattin A. Elorza Forcada
Victor Hernando Fernandez
