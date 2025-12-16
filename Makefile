BINARY_NAME=user-service
MAIN=./cmd/user-service/main.go
KIND_CLUSTER_NAME=jwt-cluster
K8S_NAMESPACE=default
PORT=8080
NODEPORT=30000
MIGRATIONS_DIR=migrations

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: all build run clean tidy docker-build migrate-up migrate-down kind-create kind-delete kind-load k8s-apply k8s-apply-secrets k8s-delete k8s-logs k8s-status deploy-kind connect

all: build

build:
	go build -o $(BINARY_NAME) $(MAIN)

run: build
	./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)

tidy:
	go mod tidy

docker-build:
	docker build --platform linux/arm64 -t $(BINARY_NAME):latest .

migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" down

kind-create:
	kind create cluster --name $(KIND_CLUSTER_NAME) || true

kind-delete:
	kind delete cluster --name $(KIND_CLUSTER_NAME) || true

kind-load: docker-build
	kind load docker-image $(BINARY_NAME):latest --name $(KIND_CLUSTER_NAME)

k8s-apply-secrets:
	@echo "📝 Создание Secret из .env..."
	@envsubst < deploy/secret.yml | kubectl apply -f -
	@echo "✅ Secret создан"

k8s-apply: k8s-apply-secrets
	kubectl apply -f deploy/configmap.yml
	kubectl apply -f deploy/deployment.yml
	kubectl apply -f deploy/service.yml

k8s-delete:
	kubectl delete -f deploy/service.yml || true
	kubectl delete -f deploy/deployment.yml || true
	kubectl delete -f deploy/configmap.yml || true
	kubectl delete secret user-secret || true
	kubectl delete -f deploy/postgres.yml || true

k8s-logs:
	kubectl logs -l app=$(BINARY_NAME) --tail=100

k8s-status:
	kubectl get pods -n $(K8S_NAMESPACE)
	kubectl get svc -n $(K8S_NAMESPACE)

deploy-kind: kind-delete kind-create kind-load k8s-apply k8s-status

connect:
	@echo "🔗 Подключаюсь к приложению..."
	kubectl port-forward svc/$(BINARY_NAME) $(PORT):$(PORT) -n $(K8S_NAMESPACE)
