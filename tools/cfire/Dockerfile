FROM python:2.7.13-alpine3.6
RUN apk add --no-cach git bash gcc musl-dev build-base libffi libc-dev libtool autoconf automake make libffi-dev
RUN apk add --update sqlite
RUN git clone https://github.com/RhinoSecurityLabs/Security-Research.git
RUN mv /Security-Research/tools/cfire/ /cfire/
WORKDIR /cfire/
RUN pip install argparse requests dnspython dnslib netaddr
RUN BUILD_LIB=1 pip install ssdeep
RUN /cfire/install_deps.sh
CMD ["python cfire.py -u"]
CMD ["/bin/ash"]
