import jwt
import datetime
import os
import redis
import logging

redis_client= redis.Redis(host='redis-logout',port=6379,db=0)
EXPIRATION = 86400
REFRESH = 604800
SECRET_KEY = os.environ.get('JWT_SECRET')

def blacklist_refresh_token(refresh,expiration_time):
    now = datetime.datetime.now().timestamp()
    remain_seconds = expiration_time-int(now)
    redis_client.setex(refresh,remain_seconds,"blacklisted")

def jwt_to_payload(token):
    try:
        logging.info(SECRET_KEY)
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
        jwt.decode(token,SECRET_KEY,algorithms='HS256')
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
    logging.info(SECRET_KEY)
    token = jwt.encode(access,SECRET_KEY,algorithm="HS256")
    refreshToken = jwt.encode(refresh,SECRET_KEY,algorithm="HS256")
    return token,refreshToken
