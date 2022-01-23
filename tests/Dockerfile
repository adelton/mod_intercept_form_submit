FROM registry.fedoraproject.org/fedora
COPY Makefile *intercept_form_submit* LICENSE README /src/
WORKDIR /src
COPY tests/build.sh /src/tests/
COPY docs/* /src/docs/
RUN tests/build.sh
COPY tests/* /src/tests/
RUN tests/config.sh
ENTRYPOINT [ "/usr/sbin/httpd", "-DFOREGROUND" ]
