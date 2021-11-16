import logging

from app.extensions import db
from app.models import User
from flask import json, jsonify
from flask_restful import Resource, reqparse
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64decode
from flask_jwt_extended import create_access_token
from datetime import timedelta
from flask import request


class Login(Resource):
    def get(self):
        if not request.headers.get("Authorization"):
            return {"error": "authorization não encontrado"}, 400

        basic, code = request.headers["Authorization"].split(" ")

        if not basic.lower() == "basic":
            return {"error": "autorizacao mal formatada."}, 400

        email, password = b64decode(code).decode().split(":")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return {"erro": "login e senha invalidos"}, 400

        token = create_access_token({"id": user.id}, expires_delta=timedelta(minutes=3))

        return {"access_token": token}


class Register(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email", required=True, help="o campo e-mail é obrigatório")
        parser.add_argument(
            "password", required=True, help="o campo password é obrigatório"
        )
        args = parser.parse_args()

        user = User.query.filter_by(email=args.email).first()

        if user:
            return {"error": "e-mail ja registrado!"}, 400

        user = User()
        user.email = args.email
        user.password = generate_password_hash(args.password, salt_length=10)

        db.session.add(user)

        try:
            db.session.commit()
            return {"message": "usuario registrado com sucesso!"}, 201
        except Exception as e:
            db.session.rollback()
            logging.critical(str(e))
            return (
                {"erro" "não foi possivel fazer o registro do usuario."},
                500,
            )
