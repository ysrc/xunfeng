nohup mongodb/Server/bin/mongod --port 65521 --dbpath=/root/app/mongodb/Data --auth  >db.log&
nohup python Run.py >web.log&
nohup python aider/aider.py > aider/aider.log &
nohup python nascan/NAScan.py > nascan/scan.log &
nohup python vulscan/VulScan.py > vulscan/vul.log &
