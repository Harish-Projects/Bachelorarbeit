**"Network Simulation for Live IDS"**

Docker Compose File; 
- The docker compose starts two containers: replay-traffic and tshark-pipeline
- replay-traffic replays the network flow using pcap files and tcpreplay program at 1Mbps
- tshark-pipeline captures the network packet and then parses (feature extraction) and then using a ML-Model predicts Threat level (0 [benign] or 1[threat]).
- finally the result is all logged in a 'Prediction.log' file under shared volume (feature_csv)

Command line Instruction: 
- Download the Docker directory.
- docker compose build
- docker compose up -d

requirements:
- https://github.com/appneta/tcpreplay/releases/download/v4.5.1/tcpreplay-4.5.1.tar.xz
- .. see Docker files