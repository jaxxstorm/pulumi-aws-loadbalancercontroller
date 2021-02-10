VERSION         := 0.0.1#$(shell pulumictl get version)
TESTPARALLELISM := 12

PACK            := awslbcontroller
PROVIDER        := pulumi-resource-${PACK}
CODEGEN         := pulumi-gen-${PACK}

WORKING_DIR     := $(shell pwd)

build:: schema provider build_go build_dotnet build_nodejs build_python

schema::
	cd provider/cmd/$(CODEGEN) && go run main.go schema ../$(PROVIDER)

provider:: schema
	rm -rf provider/cmd/$(PROVIDER)/bin
	cd provider && VERSION=${VERSION} go generate cmd/${PROVIDER}/main.go
	cd provider/cmd/$(PROVIDER) && go build -a -o $(WORKING_DIR)/bin/$(PROVIDER) main.go schema.go lbcontroller.go

build_go:: schema
	rm -rf go
	cd provider/cmd/$(CODEGEN) && go run main.go go ../../../sdk/go ../$(PROVIDER)/schema.json $(VERSION)

build_dotnet:: DOTNET_VERSION := ${VERSION}#$(shell pulumictl get version --language dotnet)
build_dotnet:: schema
	rm -rf sdk/dotnet
	cd provider/cmd/$(CODEGEN) && go run main.go dotnet ../../../sdk/dotnet ../$(PROVIDER)/schema.json $(VERSION)
	cd sdk/dotnet/ && \
		echo "${DOTNET_VERSION}" >version.txt && \
		dotnet build /p:Version=${DOTNET_VERSION}

build_nodejs:: PYPI_VERSION := ${VERSION}#$(shell pulumictl get version --language javascript)
build_nodejs:: schema
	rm -rf sdk/nodejs
	cd provider/cmd/$(CODEGEN) && go run main.go nodejs ../../../sdk/nodejs ../$(PROVIDER)/schema.json $(VERSION)
	cd sdk/nodejs/ && \
		yarn install && \
		yarn run tsc && \
		yarn run tsc --version && \
		cp ../../README.md ../../LICENSE package.json yarn.lock ./bin/ && \
		sed -i.bak -e "s/\$${VERSION}/$(VERSION)/g" ./bin/package.json

build_python:: PYPI_VERSION := ${VERSION}#$(shell pulumictl get version --language python)
build_python:: schema
	rm -rf sdk/python
	cd provider/cmd/$(CODEGEN) && go run main.go python ../../../sdk/python ../$(PROVIDER)/schema.json $(VERSION)
	cd sdk/python/ && \
		cp ../../README.md . && \
		python3 setup.py clean --all 2>/dev/null && \
		rm -rf ./bin/ ../python.bin/ && cp -R . ../python.bin && mv ../python.bin ./bin && \
		sed -i.bak -e "s/\$${VERSION}/$(PYPI_VERSION)/g" -e "s/\$${PLUGIN_VERSION}/$(VERSION)/g" ./bin/setup.py && \
		rm ./bin/setup.py.bak && \
		cd ./bin && python3 setup.py build sdist

install_nodejs_sdk:: build_nodejs
	yarn link --cwd $(WORKING_DIR)/sdk/nodejs/bin

install_dotnet_sdk:: build_dotnet
	mkdir -p $(WORKING_DIR)/nuget
	find . -name '*.nupkg' -print -exec cp -p {} ${WORKING_DIR}/nuget \;

install_go_sdk::
	# Intentionally empty for CI / CD templating

install_python_sdk::
	# Intentionall empty for CI / CD templating
