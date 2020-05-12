# WSGI service environment
FROM sourcepole/qwc-uwsgi-base:alpine-latest

# Required for pip with git repos
RUN apk add --no-cache --update git

# Required build dependencies for pillow
RUN apk add --virtual build-deps build-base linux-headers python3-dev
# Required libs for pillow
RUN apk add --no-cache --update jpeg-dev zlib-dev libjpeg

# Required for psychopg, --> https://github.com/psycopg/psycopg2/issues/684
RUN apk add --no-cache --update postgresql-dev gcc python3-dev musl-dev

ADD . /srv/qwc_service
RUN pip3 install --no-cache-dir -r /srv/qwc_service/requirements.txt
# Remove build dependencies
RUN apk del build-deps