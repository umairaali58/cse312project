FROM python:3.9

WORKDIR /usr/src/app

COPY . .

RUN pip install -r requirements.txt

EXPOSE 8080

ENV FLASK_APP=server.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080

CMD ["flask", "run"]


