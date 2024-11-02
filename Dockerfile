FROM ubuntu

ENV APP_FOLDER=/usr/src/app \
    RUST_LOG=warn \
    MG_MQ_HOST=mq \
    MG_MONGO_HOST=mongo \
    CAFILE=/run/secrets/millegrille.cert.pem \
    KEYFILE=/run/secrets/key.pem \
    CERTFILE=/run/secrets/cert.pem \
    MG_FICHIERS_URL=https://fichiers:443 \
    MG_REDIS_URL=rediss://client_rust@redis:6379#insecure \
    MG_REDIS_PASSWORD_FILE=/run/secrets/passwd.redis.txt

WORKDIR $APP_FOLDER

COPY target/release/millegrilles_core .

RUN mkdir -p /var/opt/millegrilles/archives && chown 983:980 /var/opt/millegrilles/archives && \
    apt-update && apt-get install -y ca-certificates && apt-get clean

# UID 983 mgissuer et code
# GID 980 millegrilles
USER 983:980

VOLUME /var/opt/millegrilles/archives

CMD ./millegrilles_core
