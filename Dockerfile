FROM python:3.8-slim

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

CMD ["python","app.py"]

# docker build -t jwt .
# docker run -p 5000:5000 --env-file ./.env --name jwt --network login jwt:latest