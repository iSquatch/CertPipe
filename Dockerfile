FROM python:alpine3.7
COPY . /certpipe
WORKDIR /certpipe
RUN pip install -r requirements.txt
CMD python ./certpipe.py
