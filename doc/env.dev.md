# Core de MilleGrilles

## Exposer les ports du middleware

Utiliser le script sous le projet millegrilles.instance.python, repertoire `bin/dev/publish_ports.sh` pour exposer
les ports de redis (6379), MQ (5673) et MongoDB (27017). 

Il est aussi possible de les exposer avec la commande : 

* `docker service update --publish-add 6379:6379 mq`
* `docker service update --publish-add 5673:5673 mq` 
* `docker service update --publish-add 27017:27017 mongo`

## Paramètres

<pre>
CAFILE=/var/opt/millegrilles/configuration/pki.millegrille.cert
CERTFILE=/var/opt/millegrilles/secrets/pki.core.cert
KEYFILE=/var/opt/millegrilles/secrets/pki.core.cle
MG_CERTISSUER_URL=http://localhost:2080
MG_MONGO_HOST=localhost
MG_MQ_HOST=localhost
MG_REDIS_PASSWORD_FILE=/var/opt/millegrilles/secrets/passwd.redis.txt
MG_REDIS_URL=rediss://client_rust@localhost:6379#insecure
RUST_LOG=warn,millegrilles_core::core_topologie=debug
</pre>
