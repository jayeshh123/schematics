#!/bin/bash

if [ -e ${ini_file} ]
then
    rm ${ini_file}
    echo "${ini_file} file deleted"
    echo "[scale_nodes]" >> inventory.ini
    echo "${target_ip}" >> inventory.ini

    proxy_command="ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand=\"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p root@${bastion_ip} -i /tmp/.schematics/IBM/tf_data_path/id_rsa\"'"

    echo "[scale_nodes:vars]" >> inventory.ini
    echo ${proxy_command} >> inventory.ini
fi
# ssh -o StrictHostKeyChecking=no -tt -i /tmp/.schematics/IBM/tf_data_path/id_rsa -J root@${bastion_ip} root@${target_ip} /bin/bash <<'EOT'
# echo "These commands will be run on: $( uname -a )"
# echo "They are executed by: $( whoami )"
# ls /root/
# cat /root/.ssh/authorized_keys
# exit
# EOT
