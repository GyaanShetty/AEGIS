.PHONY: help install build test fuzz gas circuit-test offchain-test compile-circuit prove verifier policy server agent dashboard

help:
	@echo "install         install foundry deps and python packages"
	@echo "build           compile contracts"
	@echo "test            run contract tests"
	@echo "fuzz            run fuzz + invariant tests hard"
	@echo "gas             gas report (the enforcement tax)"
	@echo "circuit-test    run Noir circuit tests"
	@echo "offchain-test   run python (policy/x402/adversarial) tests"
	@echo "compile-circuit nargo compile the attestation circuit"
	@echo "prove           generate + verify a period proof (needs bb)"
	@echo "verifier        write the UltraHonk Solidity verifier (needs bb)"
	@echo "policy          run policy engine on :8001"
	@echo "server          run x402 resource server on :8002"
	@echo "agent           run the agent"
	@echo "dashboard       web UI on http://localhost:8000"

offchain-test:
	cd offchain && . .venv/bin/activate && python -m pytest -q

compile-circuit:
	cd circuits/mandate_compliance && nargo compile

prove:
	cd circuits/mandate_compliance && nargo execute witness && \
	  bb prove -s ultra_honk --oracle_hash keccak -b target/mandate_compliance.json \
	    -w target/witness.gz -o target/proof && \
	  bb write_vk -s ultra_honk --oracle_hash keccak -b target/mandate_compliance.json -o target/proof && \
	  bb verify -s ultra_honk --oracle_hash keccak -k target/proof/vk -p target/proof/proof \
	    -i target/proof/public_inputs

verifier:
	cd circuits/mandate_compliance && \
	  bb write_solidity_verifier -s ultra_honk -k target/proof/vk -o target/Verifier.sol

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

# Dashboard UI on http://localhost:8000 (venv lives outside iCloud: see README)
dashboard:
	cd offchain && $(HOME)/.venvs/aegis/bin/python -m uvicorn dashboard.app:app --port 8000
