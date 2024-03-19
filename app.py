from flask import Flask, jsonify, request, make_response
from flask_cors import cross_origin
from sqlalchemy import create_engine,Table, MetaData,insert,delete,update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from func import token_issue,validate_token,jwt_to_payload,blacklist_refresh_token

import os
import logging
import redis

app = Flask(__name__)
# CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*", "allow_headers": ["Authorization", "Content-Type"]}})
AUTHORITIES_KEY = "auth"
# SECRET_Key = "d342368781b90fdd52a18d49187fa56366b5ff805bbeec9836a3811311d60b210f6f9044c840bbe8d5febeceb08d10f5d870e2af15a965634d1ff4b387535092"
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE',default='oauth2')
MYSQL_USERNAME = os.environ.get('MYSQL_USERNAME',default='login')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD',default='password')
# MYSQL_DATABASE='oauth2'
# MYSQL_USERNAME = 'login'
# MYSQL_PASSWORD = 'password'
MYSQL_HOST = 'mysql-login'
REDIS_HOST = os.environ.get('REDIS_HOST')
HEADER = 'Authorization'
SQL_URL = "mysql+pymysql://"+MYSQL_USERNAME +":"+MYSQL_PASSWORD+"@"+MYSQL_HOST+"/"+MYSQL_DATABASE
r=redis.Redis(host=REDIS_HOST,port=6379,db=0)

logging.getLogger().setLevel(logging.DEBUG)
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
    logging.info(userName)
    if not all([userName,authorities,userId]):
        return jsonify({"error": "Missing parameters"}),400

    token,refresh =token_issue(userName=userName,userId=userId,authorities=authorities)
    logging.info(token)
    return jsonify({"accessToken":token,"refreshToken":refresh})

@app.route('/jwt/reissue',methods=["GET"])
@cross_origin(allow_headers=['Authorization'])
def token_reissue():
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


@app.route("/jwt/logout",methods=["POST"])
@cross_origin(allow_headers=['Authorization'])
def logout():
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

def build_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response

def build_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0')