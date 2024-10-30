from flask import Flask, redirect, render_template, session, url_for, request
import json
import requests
from os import environ as env
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from urllib.parse import quote_plus, urlencode

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Ruta principal
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/perfil")
def perfil():
    return render_template(
        "perfil.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

# Ruta de autenticación
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

# Ruta de inicio de sesión
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

# Ruta de cierre de sesión
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

# Ruta para actualizar el perfil del usuario
@app.route("/edit-profile", methods=["POST"])
def edit_profile():
    # Extraer datos del formulario
    tipo_documento = request.form.get("tipoDocumento")
    numero_documento = request.form.get("numeroDocumento")
    direccion = request.form.get("direccion")
    telefono = request.form.get("telefono")

    # Obtener token de acceso

    auth_response = requests.post(
        'https://dev-7cxt3g6tzn1n7edg.us.auth0.com/oauth/token', 
        json={
            "client_id": "QVT9VVKSLzR6axVQPDbRMCliIvrBptQf",
            "client_secret": "Yao0ADxcQcYvNiwj32lZt9dHy7Z9AGek7JT6CAYN3eQqDd0n8m7Ng59o7UjysvRA",
            "audience": "https://dev-7cxt3g6tzn1n7edg.us.auth0.com/api/v2/",
            "grant_type": "client_credentials"
        }
        )
    auth_data = auth_response.json()
    print('DATA', auth_data)
    token = auth_data["access_token"]
    

    # Realizar la solicitud PATCH para actualizar el usuario en Auth0
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    user_id = session["user"]["userinfo"]["sub"]
    user_url = f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users/{user_id}'

    # Crear el payload para actualizar los datos de user_metadata
    update_payload = {
        "user_metadata": {
            "Tipo documento": tipo_documento,
            "NumeroDocumento": numero_documento,
            "Direccion": direccion,
            "Telefono": telefono,
        }
    }

    response = requests.patch(user_url, headers=headers, json=update_payload)

    # Validar respuesta y redirigir
    if response.status_code == 200:
        return redirect(url_for("perfil"))
    else:
        return f"Error al actualizar el perfil: {response.json()}", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
