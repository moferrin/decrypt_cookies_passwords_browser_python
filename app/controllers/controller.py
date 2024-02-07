from app.models.model import obtener_contrasenias, obtener_cookies
from flask import Flask, render_template, request, url_for, flash, redirect
from werkzeug.exceptions import abort
from app import app


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/obtener_contrasenias', methods=['POST'])
def obtener_contrasenias_c():
        salida = obtener_contrasenias()
        return  salida    


@app.route('/obtener_cookies', methods=['POST'])
def obtener_cookies_c():
        salida = obtener_cookies()
        return  salida
