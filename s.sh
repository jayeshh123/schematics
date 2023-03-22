#!/bin/bash
python3 --version


ssh -o StrictHostKeyChecking=no -tt -i /tmp/.schematics/IBM/tf_data_path/id_rsa root@${bastion_ip} /bin/bash <<'EOT'
echo "These commands will be run on: $( uname -a )"
echo "They are executed by: $( whoami )"
ls /root/
cat /root/.ssh/authorized_keys
exit
EOT
