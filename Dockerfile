FROM python:3.6-alpine

RUN apk --update --no-cache add \
    yarn && \
	mkdir -p /sarna/static/ && \
	mkdir -p /sarna/database/ && \
	mkdir -p /sarna/uploaded_data

# Add and install requirements
WORKDIR /sarna

ADD requirements.txt .
RUN apk --no-cache add build-base libxslt-dev python3-dev jpeg-dev zlib-dev && \
    pip install -r requirements.txt && \
    apk del build-base libxslt-dev python3-dev jpeg-dev zlib-dev

ADD static/package.json /sarna/static/static/
RUN cd /sarna/static && yarn install
RUN apk --no-cache add libmagic libxslt jpeg zlib

WORKDIR /sarna
COPY ./ /sarna/
RUN ls -lahtr /sarna/

EXPOSE 5000
ENTRYPOINT ["python3", "/sarna/server.py"]