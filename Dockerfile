FROM python:3.6-alpine

RUN apk --update --no-cache add \
    yarn && \
	mkdir -p /sarna/static/ && \
	mkdir -p /sarna/database/ && \
	mkdir -p /sarna/uploaded_data

ADD requirements.txt /tmp/
RUN apk --no-cache add build-base libxslt-dev python3-dev jpeg-dev zlib-dev && \
    pip install -r /tmp/requirements.txt && \
    apk del build-base libxslt-dev python3-dev jpeg-dev zlib-dev

RUN ls -lahtr /sarna/static
ADD static/package.json /sarna/static/
RUN cd /sarna/static && yarn install
RUN apk --no-cache add libmagic libxslt jpeg zlib

RUN ls -lahtr /sarna/static
WORKDIR /sarna
COPY ./ /sarna/
RUN ls -lahtr /sarna/static

EXPOSE 5000
ENTRYPOINT ["python3", "/sarna/server.py"]