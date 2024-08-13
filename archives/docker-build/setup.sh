#!bin/bash
# author: <user-name>
# Bash script to Install ansible, pip, git, wget, and atom IDE
# then pull ansible galaxy playbooks for dev environment

# Defined Variables
YUM_DIST="/etc/yum.sources.d/"
APT_DIST="/etc/apt/sources.list.d/"
YUM_INSTALL='yum install'
APT_INSTALL='sudo apt-get install'
ATOM_DEB_URL='https://atom.io/download/deb'
ATOM_YUM_URL='https://atom.io/download/rpm'

# check yum or apt
echo "checking distro " && sleep 2
if [ -d "$YUM_DIST" ]
then
 echo "Yum package distro found " && sleep 2
 INSTALL="$YUM_INSTALL"
 PKG='yum'
fi

if [ -d "$APT_DIST" ]
then
 echo "APT package distro found " && sleep 2
 INSTALL="$APT_INSTALL"
 PKG='apt'
else
  echo "could not determine yum or apt distro" && sleep 2
  end
fi

# checking pip
echo "checking pip package " && sleep 3
if ! [ -x "$(command -v pip)" ]; then
  echo 'Error: pip is not installed.' && sleep 3
  $INSTALL python-pip
else
  echo "python-pip found" && sleep 3
fi

echo "Checking if ansible is installed " && sleep 3
if ! [ -x "$(command -v ansible)" ]; then
  echo 'Error: ansible is not installed. Installing now...' && sleep 3
  pip install ansible
else
  echo "Ansible package found" && sleep 3
fi

echo "Checking if wget is installed" && sleep 3
if ! [ -x "$(command -v wget)" ]; then
  echo 'Error: wget is not installed. Installing now...' && sleep 3
  $INSTALL wget -y
else
  echo "Git package found" && sleep 3
fi

echo "Checking if git is installed" && sleep 3
if ! [ -x "$(command -v git)" ]; then
  echo 'Error: ansible is not installed. Installing now...' && sleep 3
  $INSTALL git -y
else
  echo "Git package found" && sleep 3
fi

echo "So far so good" && sleep 3
echo "installling dev environment playbooks"  && sleep 3
ansible-galaxy install <user-name>.docker_playground

echo "Dev environment nearly finished" && sleep 3

echo "Copying Alias shortcuts to /etc/profile.d/dir" && sleep 3
cp files/00-alias.sh /etc/profile.d/
source ~/.bashrc
echo "Installing ATOM IDE"
#if $INSTALL == $YUM_INSTALL
#then
echo "Installing wget"
$INSTALL wget -y

echo "create github dir "
mkdir /home/$USER/github
cd /home/$USER/github && git clone https://github.com/<user-name>/ansible-role-dev-environment.git
cd -

echo "Installing latest version of ATOM-IDE"
$INSTALL atom -y

echo "Dev environment finished" && sleep 4
echo "Open Atom IDE and setup git and platform-ide terminal extensions" && sleep 2

echo "Also..." && sleep 4
echo "Run this command to setup full dev environment" && sleep 4
# echo "ansible-playbook roles/<user-name>.dev_playground/playbook.yml" && sleep 4
pull
ansible-playbook roles/ansible-role-dev-environment/playbook.yml
