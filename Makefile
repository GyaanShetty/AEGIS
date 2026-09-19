.PHONY: help install build test fuzz gas circuit-test policy server agent

help:
	@echo "install       install foundry deps and python packages"
	@echo "build         compile contracts"
	@echo "test          run contract tests"
	@echo "fuzz          run fuzz + invariant tests hard"
	@echo "gas           gas report (the enforcement tax)"
	@echo "circuit-test  run Noir circuit tests"
	@echo "policy        run policy engine on :8001"
	@echo "server        run x402 resource server on :8002"
	@echo "agent         run the agent"

install:
	cd contracts && forge install foundry-rs/forge-std --no-commit
	pip install -r offchain/requirements.txt

build:
	cd contracts && forge build

test:
	cd contracts && forge test -vvv

fuzz:
	cd contracts && FOUNDRY_FUZZ_RUNS=50000 forge test --match-test "testFuzz|invariant" -vvv

gas:
	cd contracts && forge test --gas-report

circuit-test:
	cd circuits/mandate_compliance && nargo test

policy:
	cd offchain && uvicorn policy.main:app --port 8001 --reload

server:
	cd offchain && uvicorn server.main:app --port 8002 --reload

agent:
	cd offchain && python -m agent.run
