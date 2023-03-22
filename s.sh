#!/bin/bash
python3 --version


ssh -o StrictHostKeyChecking=no -tt -i ${key_path} root@${bastion_ip} /bin/bash <<'EOT'
echo "These commands will be run on: $( uname -a )"
echo "They are executed by: $( whoami )"
ls /root/
cat /root/.ssh/authorized_keys
exit
EOT

