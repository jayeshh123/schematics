#!/bin/bash

if [ -e ${ini_file} ]
then
    > ${ini_file}
    echo "${ini_file} file cleaned"
fi
echo "[scale_nodes]" >> ${ini_file}
echo "${target_ip}" >> ${ini_file}

proxy_command="ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand=\"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p root@${bastion_ip} -i /tmp/.schematics/IBM/tf_data_path/id_rsa\"'"

echo "[scale_nodes:vars]" >> ${ini_file}
echo ${proxy_command} >> ${ini_file}

echo "inventory file writte"
echo "################################################"
ls /etc/ssh 
echo "################################################"
ls /etc/ssh/ssh_config.d
echo "################################################"
cat /etc/ssh/ssh_config
echo "################################################"
whoami



#sudo echo "PasswordAuthentication no" >> /etc/ssh/ssh_config

#sudo sed -i -E 's/#?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

#sudo sed -i "/^[^#]*PasswordAuthentication[[:space:]]no/c\PasswordAuthentication yes" /etc/ssh/sshd_config
#sudo service sshd restart

# ssh -o StrictHostKeyChecking=no -tt -i /tmp/.schematics/IBM/tf_data_path/id_rsa -J root@${bastion_ip} root@${target_ip} /bin/bash <<'EOT'
# echo "These commands will be run on: $( uname -a )"
# echo "They are executed by: $( whoami )"
# ls /root/
# cat /root/.ssh/authorized_keys
# exit
# EOT