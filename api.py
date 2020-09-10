from flask import Flask, request, make_response, jsonify
from flask_sslify import SSLify
from flask_restx import Api, Resource, Namespace, fields, reqparse
from flask_heroku import Heroku
from ebay_helper import *
from models import User, db, Order
from os import environ
import json
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    JWTManager,
    get_jwt_identity,
    jwt_refresh_token_required,
    set_refresh_cookies,
    get_jti,
    get_raw_jwt
)
import redis
from urllib.parse import urlparse

url = urlparse(os.environ.get('REDISCLOUD_URL'))
r = redis.Redis(host=url.hostname, port=url.port, password=url.password)


ACCESS_EXPIRES = 262800000 #86400
REFRESH_EXPIRES = 262800000 #2628000
app = Flask(__name__)
app.config['SECRET_KEY'] = environ.get("SECRET_KEY")
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_SAMESITE'] = "None"
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_SECRET_KEY'] = environ.get("SECRET_KEY")
app.config['JWT_COOKIE_DOMAIN'] = '.digimater.com'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = REFRESH_EXPIRES
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']


sslify = SSLify(app)
CORS(app, supports_credentials=True)
api = Api(app, title="Digimater Backend API", version='1.0', ordered=True)
api.namespaces.pop(0)
user_namespace = api.namespace('user', description="All User Related Endpoints")
auth_namespace = api.namespace('auth', description="All Authorization Related Endpoints")
jwt = JWTManager(app)

heroku = Heroku(app)
db.init_app(app)
db.app = app
db.create_all()


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    entry = r.get(jti)
    if entry is None:
        return False
    return True

@auth_namespace.route('/ebay_login_url', methods=["GET"])
@api.doc(description="The URL that generates an eBay code which is used to generate an Access Token and Refresh Token.", responses={200: 'Success', 500: 'Internal Server Error'})
class EbayOAuth(Resource):
    def get(self):
        try:
            auth_url = generate_authorization_url()
            return {"status": "success", "data": {"url" : auth_url}}
        except Exception:
            return make_response({"status" : "error", "message" : "Something went wrong"}, 500)


@auth_namespace.route('/login', methods=['POST'])
@api.doc(responses={200: 'Success', 403: "Bad Ebay Code", 500: 'Internal Server Error'}, params={'ebay_code': {'in': 'body', 'description': 'Ebay Code', 'required': 'True', 'example': {"ebay_code": "string"}}})
class AuthorizeToken(Resource):
    def post(self):
        if not request.json or not 'ebay_code' in request.json:
            return make_response({"status" : "error", "message" : "Request data not satisfied"}, 500)
        code = request.json["ebay_code"]
        try:
            request_dict = get_access_token_from_code(code)
            if request_dict:
                ebay_access_token = request_dict["access_token"]
                ebay_refresh_token = request_dict["refresh_token"]
                user_info = get_userinfo_from_access_token(ebay_access_token)
                user = User.query.filter_by(id=user_info["userId"]).first()

                if not user:
                    user = User(
                        id = user_info["userId"],
                        access_token = ebay_access_token,
                        refresh_token = ebay_refresh_token,
                        email = "",
                        username = user_info['username'],
                        credits = 60
                    )

                    # insert the user
                    db.session.add(user)
                    db.session.commit()
                    # generate the auth token
                    access_token = create_access_token(identity=user.id, fresh=True)
                    refresh_token = create_refresh_token(user.id)
                    responseObject = make_response({
                        'status': 'success',
                        'data': {
                            'access_token': access_token,
                            'isRegistered' : '0'
                        }
                    }, 200)
                else:
                    access_token = create_access_token(identity=user.id, fresh=True)
                    refresh_token = create_refresh_token(user.id)
                    responseObject = make_response({
                        'status': 'success',
                        'data': {
                            'auth_token': access_token,
                            'isRegistered' : '1'
                        }
                    }, 200)
                set_refresh_cookies(responseObject, refresh_token)
                return responseObject
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bad code.',
                }
                return make_response(responseObject, 403)
        except Exception as e:
            return make_response({"status" : "error", "message" : str(e)}, 500)

# Endpoint for revoking the current users access token
@auth_namespace.route('/access_revoke', methods=['DELETE'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'},params={'Authorization': {'in': 'header', 'description': 'Bearer Access Token (Requires \'Bearer\' before token)'}})
class AccessRevoke(Resource):
    @jwt_required
    def delete(self):
        jti = get_raw_jwt()['jti']
        r.set(jti, 'true', ACCESS_EXPIRES + 120)
        return make_response({"status" : "success", "message" : "Access token revoked"}, 200)


# Endpoint for revoking the current users access token
@auth_namespace.route('/refresh_revoke', methods=['DELETE'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'}, params={'refresh_token_cookie': {'in': 'cookies', 'description': 'Refresh Token (This is an httpOnly cookie). CANNOT BE TESTED HERE'}})
class RefreshRevoke(Resource):
    @jwt_refresh_token_required
    def delete(self):
        jti = get_raw_jwt()['jti']
        r.set(jti, 'true', REFRESH_EXPIRES + 120)
        return make_response({"status" : "success", "message" : "Refresh token revoked"}, 200)


@auth_namespace.route('/refresh', methods=['GET'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'}, params={'refresh_token_cookie': {'in': 'cookies', 'description': 'Refresh Token (This is an httpOnly cookie). CANNOT BE TESTED HERE'}})
class RefreshToken(Resource):
    @jwt_refresh_token_required
    def get(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        responseObject = {
                        'status': 'success',
                        'data': {
                            'auth_token': new_token,
                        }
                    }
        return responseObject, 200

@auth_namespace.route('/is_good_auth', methods=['GET'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'},params={'Authorization': {'in': 'header', 'description': 'Bearer Access Token (Requires \'Bearer\' before token)'}})
class IsGoodAuth(Resource):
    @jwt_required
    def get(self):
        return {"status": "success"}

@auth_namespace.route('/is_good_auth', methods=['GET'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'},params={'Authorization': {'in': 'header', 'description': 'Bearer Access Token (Requires \'Bearer\' before token)'}})
class IsGoodAuth(Resource):
    @jwt_required
    def get(self):
        return {"status": "success"}

@user_namespace.route('/dashboard', methods=['GET'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'},params={'Authorization': {'in': 'header', 'description': 'Bearer Access Token (Requires \'Bearer\' before token)'}})
class Dashboard(Resource):
    @jwt_required
    def get(self):
        user = User.query.filter_by(id=get_jwt_identity()).first()

        if not user:
            responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist',
                }
            return make_response(responseObject, 403)
        
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'credits': user.credits
            }
        }
        return responseObject, 200

@user_namespace.route('/orders/', methods=['GET'], defaults={'_order_id': None})
@user_namespace.route('/orders/<int:_order_id>', methods=['GET'])
@api.doc(responses={200: 'Success', 400: "Invalid User Claims", 401: 'Expired/Revoked Token', 422: 'Invalid or Nonexistent JWT'},params={'Authorization': {'in': 'header', 'description': 'Bearer Access Token (Requires \'Bearer\' before token)'}})
class Orders(Resource):
    @jwt_required
    def get(self, _order_id):

        user = User.query.filter_by(id=get_jwt_identity()).first()

        if not user:
            responseObject = {
                    'status': 'fail',
                    'message': 'User/Order does not exist',
                }
            return make_response(responseObject, 403)

        if not _order_id:
            orders = Order.query.filter_by(user_id=get_jwt_identity()).all()
        else:
            orders = Order.query.filter_by(order_id=_order_id, user_id=get_jwt_identity()).all()
        responseObject = {
            'status': 'success',
            'data': [r.as_dict() for r in orders]
        }
        return responseObject, 200
        


if __name__ == '__main__':
    app.run(host='0.0.0.0')
