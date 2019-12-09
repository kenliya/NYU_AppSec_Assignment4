FROM ubuntu:18.04
RUN apt-get update && apt-get install -y python3 python3-pip
COPY ./app /app
RUN pip3 install -r /app/requirements.txt
EXPOSE 8080
CMD python3 /app/app.py