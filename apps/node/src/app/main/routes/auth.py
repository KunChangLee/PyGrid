from json import dumps

from flask import jsonif

from ..users import User
from ... import db

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = request.headers.get('access-token')
      if token is None:
          return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config[SECRET_KEY])
      except:
         return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
   return decorator
