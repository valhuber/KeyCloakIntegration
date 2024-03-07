from security.authentication_provider.abstract_authentication_provider import Abstract_Authentication_Provider
import sqlalchemy as sqlalchemy
import database.authentication_models as authentication_models
from flask import Flask
import safrs
from safrs.errors import JsonapiError
from dotmap import DotMap  # a dict, but you can say aDict.name instead of aDict['name']... like a row
from sqlalchemy import inspect
from http import HTTPStatus
import logging

# **********************
# sql auth provider
# **********************

db = None
session = None

logger = logging.getLogger(__name__)

class ALSError(JsonapiError):

    def __init__(self, message, status_code=HTTPStatus.BAD_REQUEST):
        super().__init__()
        self.message = message
        self.status_code = status_code


class UserAndRoles(DotMap):
    def check_password(self, password=None):
        # print(password)
        return password == self.password_hash

g_flask_app = None

class Authentication_Provider(Abstract_Authentication_Provider):

    @staticmethod  #val - option for auth provider setup
    def configure_auth(flask_app: Flask):
        """ Called oauthentication.py on server start, to 
        - initialize jwt
        - establish Flask end points for login.

        Args:
            flask_app (Flask): _description_
            database (object): _description_
            method_decorators (object): _description_
        Returns:
            _type_: (no return)
        """
        global g_flask_app
        g_flask_app = flask_app
        flask_app.config["JWT_PUBLIC_KEY"] = \
            Authentication_Provider.get_jwt_pubkey()
        flask_app.config['JWT_ALGORITHM'] = 'RS256'
        return


    @staticmethod  #val - option for auth provider setup
    def get_jwt_pubkey():  #val changed to use keycloak
        from flask import jsonify, request
        import sys
        import requests
        import json
        import time
        from jwt.algorithms import RSAAlgorithm
        #jwks_uri = 'https://kc.hardened.be/realms/master/protocol/openid-connect/certs'
        # TODO use env variable instead of localhost
        jwks_uri = 'http://localhost:8080/realms/kcals/protocol/openid-connect/certs'
        for i in range(100):
            try:
                oidc_jwks_uri = requests.get(jwks_uri, verify=False).json()
                break
            except:
                # waiting .. container may still be sleeping
                time.sleep(1)
        else:
            print(f'Failed to load jwks_uri {jwks_uri}')
            sys.exit(1)
        return_result = RSAAlgorithm.from_jwk(json.dumps(oidc_jwks_uri["keys"][1]))
        return return_result


    @staticmethod
    def get_user(id: str, password: str = "") -> object:
        """ Must return a row object or UserAndRole(DotMap) with attributes:

        * name

        * role_list: a list of row objects with attribute name


        Args:
            id (str): _description_
            password (str, optional): _description_. Defaults to "".

        Returns:
            object: row object is a SQLAlchemy row

                * Row Caution: https://docs.sqlalchemy.org/en/14/errors.html#error-bhk3
        """

        def row_to_dotmap(row, row_class):
            rtn_dotmap = UserAndRoles() 
            mapper = inspect(row_class)
            for each_column in mapper.columns:
                rtn_dotmap[each_column.name] = getattr(row, each_column.name)
            return rtn_dotmap

        global db, session
        if db is None:
            db = safrs.DB         # Use the safrs.DB for database access
            session = db.session  # sqlalchemy.orm.scoping.scoped_session

        user = session.query(authentication_models.User).filter(authentication_models.User.id == id).one_or_none()
        if user is None:  #Val - change note to remove try, use 1st user if none (as a temp hack?)
            logger.info(f'*****\nauth_provider: Create user for: {id}\n*****\n')
            user = session.query(authentication_models.User).first()
            #return user
        logger.info(f'*****\nauth_provider: User: {user}\n*****\n')
        # get user / roles from kc
        try_kc = 'jwt'  # enables us to turn off experimental code
        if try_kc == 'jwt':
            """ To retrieve user info from the jwt, you may want to look into these functions:

            https://flask-jwt-extended.readthedocs.io/en/stable/automatic_user_loading.html
            as used in security/system/authentication.py 
            """
            global g_flask_app
            from flask_jwt_extended import JWTManager
            from flask_jwt_extended import create_access_token
            from flask import jsonify

            user = {"id": id, "password": password}  # is this == kwargs?
            user_identity = UserAndRoles()
            user_identity.id = id
            user_identity.password = password
            # FIXME fails: JWT_PRIVATE_KEY must be set to use asymmetric cryptography algorithm "RS256"
            access_token = create_access_token(identity=user_identity)
            # now decode for user/roles info; also see jwt.io
            jswon_jwt = jsonify(access_token=user)  # this returns something with SQLAlchemy row
            pass 

            # jwt = JWTManager(g_flask_app)  # can't use this...
            # fails with: AssertionError: The setup method 'errorhandler' can no longer be called on the application. It has already handled its first request, any changes will not be applied consistently.
            # Make sure all imports, decorators, functions, etc. needed to set up the application are done before running it.

        elif try_kc == 'api':  # get jwt for user info & roles
            import requests  # not working - 404
            args = f"grant_type=password&client_id=alsclient&username={id}&password={password}"
            msg_url = f'http://localhost:8080/realms/kcals/protocol/openid-connect/token?{args}'
            r = requests.get(msg_url)
            pass

        use_db_row = True  # prior version did not return class with check_password; now fixed
        if use_db_row:
            return user
        else:
            pass
            rtn_user = row_to_dotmap(user, authentication_models.User)
            rtn_user.UserRoleList = []
            user_roles = getattr(user, "UserRoleList")
            for each_row in user_roles:
                each_user_role = row_to_dotmap(each_row, authentication_models.UserRole)
                rtn_user.UserRoleList.append(each_user_role)
            return rtn_user  # returning user fails per caution above
