FROM python:3.13-slim-trixie
MAINTAINER Max Meinhold <mxmeinhold@gmail.com>


RUN apt-get -yq update && \
    apt-get -yq --no-install-recommends install gcc libsasl2-dev libldap2-dev libssl-dev git && \
    apt-get -yq clean all

RUN mkdir /opt/eac

WORKDIR /opt/eac

RUN --mount=type=bind,source=requirements.txt,target=requirements.txt \
    pip install -r requirements.txt

COPY . /opt/eac

RUN ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

ARG PORT=8080
ENV PORT=${PORT}
EXPOSE ${PORT}

CMD ["gunicorn app:application --bind=0.0.0.0:${PORT} --access-logfile=- --timeout=600"]
