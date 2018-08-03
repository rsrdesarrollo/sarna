FROM python:3.6-alpine

RUN apk --update --no-cache add \
    yarn && \
	mkdir -p /sarna/static/ && \
	mkdir -p /sarna/uploaded_data

ADD requirements.txt /tmp/
RUN apk --no-cache add --virtual build-deps build-base libxslt-dev python3-dev jpeg-dev zlib-dev postgresql-dev musl-dev&& \
    pip install -r /tmp/requirements.txt && \
    apk del build-deps &&\
    apk --no-cache add libmagic libxslt jpeg zlib libpq

ADD static/package.json /sarna/static/
RUN cd /sarna/static && yarn install

WORKDIR /sarna
COPY ./ /sarna/

ENV FLASK_ENV=development

EXPOSE 5000
ENTRYPOINT ["/sarna/entrypoint.sh"]
