import jwt
import datetime
import os
import redis
import logging

redis_client= redis.Redis(host='redis-logout',port=6379,db=0)
EXPIRATION = 86400
REFRESH = 604800
SECRET_KEY = os.environ.get('JWT_SECRET',default="d342368781b90fdd52a18d49187fa56366b5ff805bbeec9836a3811311d60b210f6f9044c840bbe8d5febeceb08d10f5d870e2af15a965634d1ff4b387535092")

def blacklist_refresh_token(refresh,expiration_time):
    now = datetime.datetime.now().timestamp()
    remain_seconds = expiration_time-int(now)
    redis_client.setex(refresh,remain_seconds,"blacklisted")

def jwt_to_payload(token):
    try:
        decoded = jwt.decode(token,SECRET_KEY,algorithms='HS512')
        return decoded
    except jwt.ExpiredSignatureError:
        logging.info("만료")
        return None
    except jwt.InvalidTokenError:
        logging.info("토큰이상")
        return None

def validate_token(token):
    try:
        jwt.decode(token,SECRET_KEY,algorithms='HS512')
        return True
    except jwt.ExpiredSignatureError:
        logging.info("만료")
        return False
    except jwt.InvalidTokenError:
        logging.info("잘못된 토근 형식")
        return False

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
