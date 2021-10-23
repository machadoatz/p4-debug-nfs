ifndef BUILD_DIR
BUILD_DIR=build
endif

ifndef PCAP_DIR
PCAP_DIR=pcaps
endif

ifndef LOG_DIR
LOG_DIR=logs
endif

ifndef BMV2
BMV2=/home/user/p4-guide/bin/behavioral-model
endif

all: compile

compile: dirs
	$(foreach p4_file, $(wildcard *.p4), \
		sudo p4c-bm2-ss \
        	--std p4-16 \
        	--p4runtime-files $(BUILD_DIR)/$(basename $(p4_file)).p4info.txt \
        	-o $(BUILD_DIR)/$(basename $(p4_file)).json \
        	$(p4_file);)

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

switch:
	# disable ipv6
	sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1
	sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
	sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
	
	# `sudo` is required because of mininet
	export PYTHONPATH=/home/user/.local/bin/mn;
	sudo -E python3 ../run_nf.py \
    	-b $(BMV2)/targets/simple_switch_grpc/simple_switch_grpc \
    	-t topology.json

controller:
	PYTHONPATH=$(PYTHONPATH):../ python3 controller.py \
    	--grpc-addr "0.0.0.0:50051" \
    	--p4info build/main.p4info.txt \
    	--bmv2-json build/main.json

clean:
	sudo rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
	sudo mn -c
