from flask import Flask, jsonify, request
from sqlalchemy import create_engine,Table, MetaData,insert,delete,update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

import os
import jwt
import datetime
import hashlib

app = Flask(__name__)

AUTHORITIES_KEY = "auth"
EXPIRATION = 86400
REFRESH = 604800
SECRET_KEY = os.environ.get('JWT_SECRET',default="d342368781b90fdd52a18d49187fa56366b5ff805bbeec9836a3811311d60b210f6f9044c840bbe8d5febeceb08d10f5d870e2af15a965634d1ff4b387535092")
# SECRET_Key = "d342368781b90fdd52a18d49187fa56366b5ff805bbeec9836a3811311d60b210f6f9044c840bbe8d5febeceb08d10f5d870e2af15a965634d1ff4b387535092"
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE',default='oauth2')
MYSQL_USERNAME = os.environ.get('MYSQL_USERNAME',default='login')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD',default='password')
# MYSQL_DATABASE='oauth2'
# MYSQL_USERNAME = 'login'
# MYSQL_PASSWORD = 'password'
MYSQL_HOST = 'mysql-login'

PREFIX="Bearer "
HEADER = "Authorization"
SQL_URL = "mysql+pymysql://"+MYSQL_USERNAME +":"+MYSQL_PASSWORD+"@"+MYSQL_HOST+"/"+MYSQL_DATABASE

Base = declarative_base()
engine = create_engine(SQL_URL,echo=True)
metadata_obj = MetaData(bind =engine)
SessionLocal = sessionmaker(autocommit=False,autoflush=False,bind=engine)
db=SessionLocal()
member_table = Table("member",metadata_obj,autoload_with=engine)

@app.route('/jwt/issue', methods = ['GET'])
def token_request():
    userName = request.args.get('userName')
    authorities = request.args.get('authorities')
    userId = request.args.get('userId')
    if not all([userName,authorities,userId]):
        return jsonify({"error": "Missing parameters"}),400

    token,refresh =token_issue(userName=userName,userId=userId,authorities=authorities)
    return jsonify({"accessToken":token,"refreshToken":refresh})

def token_issue(userId,userName,authorities):
    access = {
        'sub': userId,
        'name': userName,
        'auth': authorities,
        'exp': datetime.datetime.now() + datetime.timedelta(seconds=EXPIRATION)
    }
    refresh = {
        'sub': userId,
        'name': userName,
        'auth': authorities,
        'exp': datetime.datetime.now() + datetime.timedelta(seconds=REFRESH)
    }
    token = jwt.encode(access,SECRET_KEY,algorithm="HS512")
    refreshToken = jwt.encode(refresh,SECRET_KEY,algorithm="HS512")
    return token,refreshToken
    

@app.route('/jwt/reissue',methods=["GET"])
def token_reissue():
    header = request.headers.get[HEADER]
    if header:
        token = header.split(' ')[1] if ' 'in header else header
    # 헤더 유효한지 확인
        if(validate_token(token)):
            return jsonify({"error":"유효하지 않은 토큰"}),400
    # mysql의 member테이블에 저장된 refresh_token과 동일한지 확인
        payload = jwt_to_payload(token)
        if(payload==None):
            return jsonify({"error":"유효하지 않은 토큰"}),400
        userId = payload.get('sub')
        userName = payload.get('name')
        userAuth = payload.get('auth')
        member = db.query(member_table).filter_by(id=userId).first()
        if(member.get('refresh_token')!=token):
            return jsonify({"error":"유효하지 않은 토큰"}),400
    # 동일하고 refresh_token이 만료되지 않았다면 재발급
        access,refresh = token_issue(userId=userId,userName=userName,authorities=userAuth)
        return jsonify({"accessToken":access,"refreshToken":refresh})

    # 재발급
    else:
        return jsonify({"error":"유효하지 않은 토큰"}),400

def jwt_to_payload(token):
    try:
        decoded = jwt.decode(token,SECRET_KEY,algorithms='HS512')
        userID = decoded.get('sub')
        return userID
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    else:
        return None

def validate_token(token):
    try:
        jwt.decode(token,SECRET_KEY,algorithms='HS512')
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    else:
        return True

if __name__ == '__main__':
    app.run()