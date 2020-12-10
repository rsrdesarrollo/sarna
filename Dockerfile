FROM python:3.6-alpine

# Create a group and user
RUN addgroup -S sarnag && adduser -S sarnau -G sarnag

RUN apk --update --no-cache add \
    yarn && \
	mkdir -p /home/sarnau/sarna/static/ && \
	mkdir -p /home/sarnau/sarna/uploaded_data

ADD requirements.txt /tmp/
RUN apk --no-cache add --virtual build-deps build-base libxslt-dev python3-dev jpeg-dev zlib-dev postgresql-dev musl-dev libffi-dev && \
    pip install -r /tmp/requirements.txt && \
    apk del build-deps &&\
    apk --no-cache add libmagic libxslt jpeg zlib libpq

ADD static/package.json /home/sarnau/sarna/static/
ADD jira_ssl_cert.crt /

RUN cd /home/sarnau/sarna/static && yarn install

WORKDIR /home/sarnau/sarna

#RUN echo "1"

COPY ./ /home/sarnau/sarna/

ENV FLASK_ENV=production

EXPOSE 5000

# Tell docker that all future commands should run as the sarnau user
RUN chown -R sarnau:sarnag /home/sarnau/sarna
USER sarnau

ENTRYPOINT ["/home/sarnau/sarna/entrypoint.sh"]
