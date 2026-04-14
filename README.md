python test_send.py -o <e/u/m> -n <int> -t <int> --local-host <local_ip> --remote-host <remote_ip>
python test_send.py -o m -n 20 -t 2000 --local-host 192.168.0.101 --remote-host 192.168.0.100
python test_send.py -o m -n 100 -t 100 --log-file adsb_metrics.csv --local-host 192.168.0.101 --remote-host 192.168.0.100
python test_receiver.py