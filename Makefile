PROJ?=ry4nz/samlidp
IDP_URL?=localhost

run:
	docker run --rm -p 637:8000 -e IDP_URL=${IDP_URL} ${PROJ}

build:
	docker build -t ${PROJ} -f Dockerfile .

push:
	docker push ${PROJ}

clean:
	docker rmi --force ${PROJ} || /bin/true

.PHONY: build clean run