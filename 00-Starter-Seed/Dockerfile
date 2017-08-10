FROM python:3-alpine

WORKDIR /home/app

#If we add the requirements and install dependencies first, docker can use cache if requirements don't change
ADD requirements.txt /home/app
RUN pip install -r requirements.txt

ADD . /home/app
CMD python server.py

EXPOSE 3000