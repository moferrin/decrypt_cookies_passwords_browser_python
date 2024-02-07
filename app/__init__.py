from flask import Flask, render_template, request

app = Flask(__name__, template_folder="views/templates")
app.secret_key = "75fc78df8vhj92gv92yvhz"


from app.controllers import controller