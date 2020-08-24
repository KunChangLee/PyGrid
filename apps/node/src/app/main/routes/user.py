import logging
from secrets import token_hex
from json import dumps, loads
from json.decoder import JSONDecodeError

import jwt
from syft.codes import RESPONSE_MSG
from flask import request, Response
from werkzeug.security import generate_password_hash, check_password_hash

from ..core.exceptions import (
    UserNotFoundError,
    RoleNotFoundError,
    AuthorizationError,
    PyGridError,
    MissingRequestKeyError,
)
from .. import main_routes
from ..users import Role, User
from ... import db


def model_to_json(model):
    """Returns a JSON representation of an SQLAlchemy-backed object."""
    json = {}
    for col in model.__mapper__.attrs.keys():
        json[col] = getattr(model, col)

    return json


def identify_user(request):
    private_key = request.headers.get("private-key")
    if private_key is None:
        raise MissingRequestKeyError

    usr = db.session.query(User).filter_by(private_key=private_key).one_or_none()
    if usr is None:
        raise UserNotFoundError

    usr_role = db.session.query(Role).get(usr.role)
    if usr_role is None:
        raise RoleNotFoundError

    return usr, usr_role


@main_routes.route('/users', methods=['POST'])
def signup_user():
    status_code = 200  # Success
    response_body = {}

    try:
        usr, usr_role = identify_user(request)
    except Exception as e:
        logging.warning("Existing user could not be linked", exc_info=e)

    try:
        data = loads(request.data)
        password = data['password']
        email = data['email']
        role = data.get('role', None)
        private_key = token_hex(32)
        hashed_password = generate_password_hash(password, method='sha256')

        if role is not None and usr_role is not None and usr_role.can_create_users:
            new_user = User(email=email, hashed_password=hashed_password,
                             private_key=private_key, role=role)
        else:
            role = db.session.query(Role).filter_by(name="User").first()
            new_user = User(email=email, hashed_password=hashed_password,
                             private_key=private_key, role=role.id)

        db.session.add(new_user)
        db.session.commit()

        user = model_to_json(new_user)
        user.pop('hashed_password', None)
        user.pop('salt', None)
        
        response_body = {RESPONSE_MSG.SUCCESS: True, "user": user}

    except (KeyError, TypeError, JSONDecodeError) as e:
        status_code = 400  # Bad Request
        response_body[RESPONSE_MSG.ERROR] = str(e)

    return Response(
        dumps(response_body), status=status_code, mimetype="application/json"
    )
