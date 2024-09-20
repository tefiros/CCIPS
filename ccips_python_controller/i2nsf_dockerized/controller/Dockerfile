FROM alpine:3.16.0
RUN apk update && apk add python3 git bash py-pip curl 
COPY cne-i2nsf_controller /cne-i2nsf_controller

RUN pip install -r /cne-i2nsf_controller/requirements.txt
RUN pip install connexion[swagger-ui]

WORKDIR /cne-i2nsf_controller
EXPOSE 5000
ENTRYPOINT ["python3","api.py"]
