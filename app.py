from flask import Flask, jsonify, request, make_response
from flask_cors import cross_origin
from flask_restx import Api,Resource, reqparse
from sqlalchemy import create_engine,Table, MetaData,insert,delete,update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from func import token_issue,validate_token,jwt_to_payload,blacklist_refresh_token

import os
import logging
import redis

app = Flask(__name__)
api = Api(app, version='1.0', title='API문서', description='JWT API 소개', doc="/api-docs")

HEADER = 'Authorization'
logging.getLogger().setLevel(logging.DEBUG)

### DB연결 - mysql
# MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE',default='oauth2')
# MYSQL_USERNAME = os.environ.get('MYSQL_USERNAME',default='login')
MYSQL_USERNAME = 'login'
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD',default='password')
# MYSQL_HOST = 'mysql-login'
MYSQL_HOST = 'localhost'
SQL_URL = "mysql+pymysql://login:"+MYSQL_PASSWORD+"@"+MYSQL_HOST+"/oauth2"

Base = declarative_base()
engine = create_engine(SQL_URL,echo=True)
metadata_obj = MetaData(bind =engine)
SessionLocal = sessionmaker(autocommit=False,autoflush=False,bind=engine)
db=SessionLocal()
member_table = Table("member",metadata_obj,autoload_with=engine)
### DB연결

### DB연결 - redis
REDIS_HOST = os.environ.get('REDIS_HOST')

r=redis.Redis(host=REDIS_HOST,port=6379,db=0)
### DB연결


### JWT 발급 로직
issue = api.namespace('issue', description = 'JWT 발급')

user_parser = reqparse.RequestParser()
user_parser.add_argument('userName', required=True, help="cannot be blank")
user_parser.add_argument('userId', required=True, help="cannot be blank")
user_parser.add_argument('userAuthorities', required=True, help="cannot be blank")

@issue.route()
class token_request(Resource):
    @issue.expect(user_parser)
    def get(self):
        """JWT 발급"""
        userName = request.args.get('userName')
        authorities = request.args.get('authorities')
        userId = request.args.get('userId')
        if not all([userName,authorities,userId]):
            return jsonify({"error": "Missing parameters"}),400

        token,refresh =token_issue(userName=userName,userId=userId,authorities=authorities)
        logging.info(token)
        return jsonify({"accessToken":token,"refreshToken":refresh})

### JWT 재발급 로직
refresh = api.namespace('reissue', description = 'JWT 재발급')

refresh_parser = reqparse.RequestParser()
refresh_parser.add_argument("Authorization", help="Bearer {refresh_token}", type=str, required=True,location="headers",default="Bearer ")

@refresh.route()
class token_reissue(Resource):
    @refresh.expect(refresh_parser)
    def get(self):
        """유효한 refresh토큰으로 JWT 재발급"""
        header = request.headers.get('Authorization')
        logging.info("header = " + request.headers.__str__())
        if header:
            token = header.split(' ')[1] if ' 'in header else header
        # 헤더 유효한지 확인
            logging.info(token)
            if(validate_token(token)==False):
                return jsonify({"error":"유효하지 않은 토큰(1)"}),400
        # 토큰이 유효한지 확인
            payload = jwt_to_payload(token)
            userId = payload.get('sub')
            # type(userId)
            logging.info("userID : ",userId,"type : ",type(userId))
            userName = payload.get('name')
            userAuth = payload.get('auth')
            member = db.query(member_table).filter_by(id=userId).first()
            if member is not None and member.refresh_token != token:
                return jsonify({"error":"유효하지 않은 토큰(3)"}),400
        # 유저 디비의 값과 refresh_token이 같은지 확인
            access,refresh = token_issue(userId=userId,userName=userName,authorities=userAuth)
            db.query(member_table).filter_by(id=userId).update({"refresh_token":refresh})
            return jsonify({"accessToken":access,"refreshToken":refresh})
        # 재발급
        else:
            return jsonify({"error":"유효하지 않은 토큰(4)"}),400

### JWT 만료 로직
logout = api.namespace('logout', description = '만료')

resource_parser = reqparse.RequestParser()
resource_parser.add_argument("Authorization", help="Bearer {access_token}", type=str, required=True,location="headers",default="Bearer ")

# @app.route("/jwt/logout",methods=["POST"])
# @cross_origin(allow_headers=['Authorization'])
@logout.route()
class logout(Resource):
    """유효한 access토큰을 만료시킴"""
    @logout.expect(resource_parser)
    def post(self):
        # if request.method == 'OPTIONS':
        #     return build_preflight_response()
        header = request.headers.get('Authorization')
        print("Received headers:",request.headers)
        #access토큰을 사용하여 요청 -> refresh토큰은 유저 디비에서 삭제, access토큰은 블랙리스트 추가
        if header:
            token = header.split(' ')[1] if ' ' in header else header
            if(validate_token(token)==False):
                return jsonify({"error":"유효하지 않은 토큰"}),400
            #토큰 유효한지 검사
            payload = jwt_to_payload(token)
            userId = payload.get('sub')
            member = db.query(member_table).filter_by(id=userId).first()
            if member:
                db.query(member_table).filter_by(id=userId).update({"refresh_token":None})
                db.commit()
                blacklist_refresh_token(token,payload.get('exp'))
                
                return jsonify("success")
            else:
                return jsonify({"error":"사용자를 찾을 수 없음"}),404
            #유저 디비에서 refresh 삭제

            #blacklist에 accessToken등록

        return jsonify("success")

if __name__ == '__main__':
    app.run(host='0.0.0.0')