#!/bin/bash
python3 --version


ssh -tt -i /tmp/.schematics/IBM/tf_data_path/id_rsa root@52.118.98.39 /bin/bash <<'EOT'
echo "These commands will be run on: $( uname -a )"
echo "They are executed by: $( whoami )"
ls /root/
cat /root/jay.txt
exit
EOT
