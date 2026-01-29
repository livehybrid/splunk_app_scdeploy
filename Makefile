SHELL := /bin/bash
pwd := ${PWD}
dirname := $(notdir $(patsubst %/,%,$(CURDIR)))
SPLUNK_HOST ?= localhost
SPLUNK_MGMT_PORT ?= 8089
SPLUNK_WEB_PORT ?= 8000
SPLUNK_HEC_PORT ?= 8088
.DEFAULT_GOAL := list
.PHONY: dist

guard-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi

APP_ID:
 APP_ID:= $(shell basename $(PWD))

list: help

help: ## Show this help message.
	@echo 'usage: make [target] ...'
	@echo
	@echo 'targets:'
	@egrep '^(.+)\:\ ##\ (.+)' $(MAKEFILE_LIST) | column -t -c 2 -s ':#' | sed 's/^/  /'

tmp/:
	mkdir -p ./tmp

clean-tests: ## Remove any previous test files/logs
	@rm -rf ./tmp/reports || true
	@rm -rf ./tmp/events.pickle || true
	@rm -f *_events.lock || true
	@rm -f *_events || true
	@rm -f helmut.log || true
	@rm -f generator.lock || true
	@rm -f pytest_splunk_addon.log || true
	@rm -rf ./assets || true
	@rm -rf ./.pytest_cache || true
	@rm -rf .tokenized_events

clean-build: ## Remove any previous app build/packaging/dist output
	@rm -rf ./build || true
	@rm -rf ./dist || true
	@rm -rf ./output || true

clean: ## Remove local build (clean-build), test (clean-tests), docker (clean-docker) + result data
clean: clean-tests clean-docker clean-build
	@rm -rf ./tmp || true

clean-venv: ## Remove the Python virtualenv
	@rm -rf ./.venv || true

clean-docker: ## Remove unused docker volumes (use with care)
	poetry run docker volume prune -f

clean-all: ## Deep clean! (venv/docker/build/test/output)
clean-all: clean-venv clean clean-docker

reinstall: ## Perform a Deep clean (clean-all) followed by an install
reinstall: clean-all install

git-init-submodules: ## Initialise the submodules configured in .gitmodules
	mkdir -p ./_submodules || true
	git submodule sync
	git submodule update --init

splunk-btool: ## Generate a btool output from the current running splunk docker container
	# No response with exit code = 0 is Good.
	docker-compose exec splunk /bin/sh -c 'sudo /opt/splunk/bin/splunk btool check'

splunk-restart: ## Restart the splunk process in the current running splunk docker container
	docker-compose exec splunk /bin/sh -c 'sudo /opt/splunk/bin/splunk restart'

install: ## Run repo installation (Poetry install)
	poetry install --no-root

update: ## Update poetry as per local config
	poetry update

docker-build:  ## Build Splunk docker container ready for side-loading of application and testing
docker-build: APP_ID
	@\
	COMPOSE_DOCKER_CLI_BUILD=1 \
	DOCKER_BUILDKIT=1 \
	BUILDKIT_PROGRESS=plain \
	APP_ID=${APP_ID} \
	DOCKER_IMAGE=$${DOCKER_IMAGE:-splunk/splunk} \
	SPLUNK_VERSION=$${SPLUNK_VERSION:-latest} \
	poetry run docker-compose -f docker-compose.yml -f docker-compose.local.yml build \
		--build-arg DOCKER_IMAGE=$${DOCKER_IMAGE:-splunk/splunk} \
		--build-arg SPLUNK_VERSION=$${SPLUNK_VERSION:-latest} \
		--build-arg HOST_UID="$$(id -u)" \
		--build-arg HOST_GID="$$(id -g)" \
		--pull

down: ## Shutdown and remove docker containers assosicated with this app/repo
down: APP_ID
	poetry run docker-compose down --remove-orphans

up: ## Start docker containers associated with this app/folder as defined in docker-compose.yml
up: APP_ID
	APP_ID=${APP_ID} poetry run docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d
	APP_ID=${APP_ID} poetry run scripts/wait-for-log-line.sh splunk 'Ansible playbook complete'

local-dev: ## Build app, build Docker image, start local Splunk (ports 8000/8088/8089). Use for testing without Splunk Cloud.
local-dev: APP_ID build
	@echo "=== Building Splunk image (using splunk/splunk:latest; proxy env vars cleared to avoid proxyconnect errors) ==="
	@unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy 2>/dev/null; \
	DOCKER_IMAGE=splunk/splunk SPLUNK_VERSION=latest APP_ID=${APP_ID} poetry run docker-compose -f docker-compose.yml -f docker-compose.local.yml build \
		--build-arg DOCKER_IMAGE=splunk/splunk \
		--build-arg SPLUNK_VERSION=latest \
		--build-arg HOST_UID="$$(id -u)" \
		--build-arg HOST_GID="$$(id -g)" \
		--pull
	@echo "=== Starting local Splunk (docker-compose) ==="
	APP_ID=${APP_ID} poetry run docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d
	@echo "Waiting for Splunk to be ready (may take 1-2 min on first run)..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
		if APP_ID=${APP_ID} poetry run docker-compose -f docker-compose.yml -f docker-compose.local.yml logs splunk 2>/dev/null | grep -qE 'Ansible playbook complete|Listening on|Boot complete|splunkd'; then \
			echo " Splunk is up."; break; \
		fi; \
		echo -n .; sleep 5; \
		if [ $$i -eq 20 ]; then echo " Timeout; try http://localhost:8000 in a minute (admin / Chang3d!)"; fi; \
	done
	@echo ""
	@echo "Local Splunk:"
	@echo "  Web UI:    http://localhost:$(SPLUNK_WEB_PORT)  (admin / Chang3d!)"
	@echo "  REST API:  https://localhost:$(SPLUNK_MGMT_PORT)"
	@echo "  Test with: make local-obtain-token && make local-create-accounts && make local-configure-destinations && make local-generate-tokens"
	@echo "  Override:  export SPLUNK_MGMT_PORT=9089 SPLUNK_WEB_PORT=9000 SPLUNK_HEC_PORT=9088  (match docker-compose.local.yml)"
	@echo "  Or set:    export SPLUNK_HOST=localhost SPLUNK_PORT=$(SPLUNK_MGMT_PORT) SPLUNKCLOUD_STACK_URL=localhost SPLUNKCLOUD_ADMIN_USER=admin SPLUNKCLOUD_ADMIN_PASSWORD=Chang3d!"
	@echo "  Then run:  poetry run python3 scripts/obtain_splunk_token.py && poetry run python3 scripts/create_test_accounts.py --host localhost --token \$$SPLUNK_TOKEN ..."

local-obtain-token: ## Obtain a Splunk token for local Docker (writes SPLUNK_TOKEN to env)
	@export SPLUNK_HOST=localhost SPLUNK_PORT=$(SPLUNK_MGMT_PORT) SPLUNKCLOUD_STACK_URL=localhost SPLUNKCLOUD_ADMIN_USER=admin SPLUNKCLOUD_ADMIN_PASSWORD=Chang3d!; \
	export SPLUNK_TOKEN=$$(poetry run python3 scripts/obtain_splunk_token.py --host localhost --port $(SPLUNK_MGMT_PORT) --username admin --password Chang3d! --scheme https --format raw 2>/dev/null); \
	echo "SPLUNK_TOKEN=$$SPLUNK_TOKEN" | head -c 50; echo "..."; \
	echo "Run: export SPLUNK_TOKEN=\$$(poetry run python3 scripts/obtain_splunk_token.py --host localhost --port $(SPLUNK_MGMT_PORT) --username admin --password Chang3d! --scheme https --format raw)"

local-create-accounts: ## Create test accounts on local Docker Splunk (admin / Chang3d!)
	SPLUNK_HOST=localhost SPLUNK_PORT=$(SPLUNK_MGMT_PORT) SPLUNKCLOUD_STACK_URL=localhost SPLUNKCLOUD_ADMIN_USER=admin SPLUNKCLOUD_ADMIN_PASSWORD=Chang3d! \
	poetry run python3 scripts/create_test_accounts.py \
		--host localhost --port $(SPLUNK_MGMT_PORT) --username admin --password Chang3d! --scheme https \
		--output test_accounts.json

local-configure-destinations: ## Configure app destinations on local Splunk (set GITHUB_*, GITLAB_*, AWS_*, OP_* for destinations)
	SPLUNK_HOST=localhost SPLUNK_PORT=$(SPLUNK_MGMT_PORT) SPLUNKCLOUD_STACK_URL=localhost SPLUNKCLOUD_ADMIN_USER=admin SPLUNKCLOUD_ADMIN_PASSWORD=Chang3d! \
	poetry run python3 scripts/configure_app_destinations.py \
		--host localhost --port $(SPLUNK_MGMT_PORT) --username admin --password Chang3d! --scheme https \
		--from-env

local-generate-tokens: ## Generate test tokens on local Splunk (run after configure-destinations and create-accounts)
	SPLUNK_HOST=localhost SPLUNK_PORT=$(SPLUNK_MGMT_PORT) SPLUNKCLOUD_STACK_URL=localhost SPLUNKCLOUD_ADMIN_USER=admin SPLUNKCLOUD_ADMIN_PASSWORD=Chang3d! \
	poetry run python3 scripts/generate_test_tokens.py \
		--host localhost --port $(SPLUNK_MGMT_PORT) --username admin --password Chang3d! --scheme https \
		--output token_results.json

up-ci: APP_ID
up-ci: ## Start docker containers (CI Only)
	poetry run scripts/ci-up.sh $(APP_ID)

#up-ci:
#	poetry run docker-compose up -d
#	docker network connect $(docker inspect $(docker-compose ps -q splunk) -f '{{json .NetworkSettings.Networks }}' | jq -r 'keys[]' | head -n 1 ) $(grep -o -P -m1 'docker.*\K[0-9a-f]{64,}' /proc/self/cgroup)
##	scripts/wait-for-log-line.sh splunk 'Ansible playbook complete'

test: ## Run PyTest against the Splunk application
test: tmp/ clean-tests splunk-ports-output
	poetry run pytest --splunk-host=$(SPLUNK_HOST) --splunk-port=$(PORTSPLUNKREST) --splunk-hec-port=$(PORTSPLUNKHEC) --splunkweb-port=$(PORTSPLUNKWEB)

build: ## Determine if UCC/Basic application and create app output
build: clean-build APP_ID
	@echo "building"
	@# If it is a UCC app then use ucc-gen else run custom build code
	@# Unset PYTHONPATH to ensure Poetry's virtual environment takes precedence over lib/
	@if [ -f ./globalConfig.json ]; then \
		PYTHONPATH= poetry run ucc-gen --ta-version $$(scripts/get-version.sh) -o output -v; \
	else \
		PYTHONPATH= poetry run scripts/build.sh; \
	fi
	mv output/$(APP_ID) output/app
#	@echo "Fix to allow boto3 to be uploaded"
#	sed -i.bak -e '267,282d' output/app/lib/botocore/session.py
#	rm -f output/app/lib/botocore/session.py.bak

release: ## Create application release
release: dist APP_ID

acsupload: ## Upload to Admin Config Service (ACS)
	poetry run ./scripts/acscli_upload.sh

dist: 
	mkdir -p tmp/reports
	PYTHONPATH= poetry run scripts/package.sh output/app

splunk-ports:
	@$(eval PORTSPLUNKWEB=$(shell poetry run docker-compose port splunk 8000 2>/dev/null | cut -d":" -f 2))
	@$(eval PORTSPLUNKREST=$(shell poetry run docker-compose port splunk 8089 2>/dev/null | cut -d":" -f 2))
	@$(eval PORTSPLUNKHEC=$(shell poetry run docker-compose port splunk 8088 2>/dev/null | cut -d":" -f 2))

splunk-ports-output: ## Print dynamic docker Splunk ports (Web/REST/HEC) to stdout
splunk-ports-output: splunk-ports
	@echo Splunk Web is running at http://localhost:$(PORTSPLUNKWEB)
	@echo Splunk REST is running at https://localhost:$(PORTSPLUNKREST)
	@echo Splunk HEC is running at https://localhost:$(PORTSPLUNKHEC)

splunk-cloud-upload: ## Upload application to SplunkCloud - Requires stack=<stackName>
splunk-cloud-upload: guard-stack
	@echo "Upload to SplunkCloud"
	@echo $(stack)
	poetry run ./scripts/doUpload.sh $(stack)

deploy-to-cloud: ## Build, package, and upload app to Splunk Cloud via ACS
deploy-to-cloud:
	@echo "=== Deploying App to Splunk Cloud ==="
	@./scripts/install_app_to_splunkcloud.sh

configure-destinations: ## Configure app destinations from environment variables
configure-destinations:
	@echo "=== Configuring App Destinations ==="
	@if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then \
		echo "Error: Splunk Cloud credentials not set. Source secrets first:"; \
		echo "  source scripts/get_secrets_from_1password.sh"; \
		exit 1; \
	fi
	@python3 scripts/configure_app_destinations.py \
		--host $$SPLUNKCLOUD_STACK_URL \
		--port 8089 \
		--username $$SPLUNKCLOUD_ADMIN_USER \
		--password "$$SPLUNKCLOUD_ADMIN_PASSWORD" \
		--scheme https \
		--from-env

create-accounts: ## Create test accounts in Splunk
create-accounts:
	@echo "=== Creating Test Accounts ==="
	@if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then \
		echo "Error: Splunk Cloud credentials not set. Source secrets first:"; \
		echo "  source scripts/get_secrets_from_1password.sh"; \
		exit 1; \
	fi
	@python3 scripts/create_test_accounts.py \
		--host $$SPLUNKCLOUD_STACK_URL \
		--port 8089 \
		--username $$SPLUNKCLOUD_ADMIN_USER \
		--password "$$SPLUNKCLOUD_ADMIN_PASSWORD" \
		--scheme https

generate-tokens: ## Generate test tokens for all configured destinations
generate-tokens:
	@echo "=== Generating Test Tokens ==="
	@if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then \
		echo "Error: Splunk Cloud credentials not set. Source secrets first:"; \
		echo "  source scripts/get_secrets_from_1password.sh"; \
		exit 1; \
	fi
	@python3 scripts/generate_test_tokens.py \
		--host $$SPLUNKCLOUD_STACK_URL \
		--port 8089 \
		--username $$SPLUNKCLOUD_ADMIN_USER \
		--password "$$SPLUNKCLOUD_ADMIN_PASSWORD" \
		--scheme https
validate-tokens: ## Validate that tokens were created and are working
validate-tokens:
	@echo "=== Validating Tokens ==="
	@python3 scripts/validate_tokens.py --from-env

test-cloud: ## Full test workflow: deploy, configure, create accounts, generate tokens, validate
test-cloud: deploy-to-cloud configure-destinations create-accounts generate-tokens validate-tokens
	@echo ""
	@echo "=== Test Workflow Complete ==="
	@echo "All steps completed successfully!"