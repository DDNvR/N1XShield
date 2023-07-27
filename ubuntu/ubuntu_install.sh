#!/bin/bash
# N1XShield

#todo still

#. when using the LOG target, consider the IO load on a busy machine; you don't want to DOS it by overwhelming the disk with log messages; I'd consider moving the PSAD LOG rules until after the stuff you're going to drop anyway;
#. dropping invalid source addresses: list can be expanded, see https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml and consider  Globally Reachable=False;
#. move the 'Allow Ping' rule above the earlier rule that accepts all ICMP with a 1/s rate limit;
#. when accepting new TCP connections, check for SYN flag (--syn is the shortcut I use);
#. when rejecting TCP connections (the per-IP connection limit rule) consider adding '--reject-with tcp-reset' which, to be fair, is probably a matter of taste; I think REJECT sends ICMP port unreachable by default;
#. consider also dropping ICMP redirects (https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Redirect) which can be misused for MITM purposes; possibly better done with the net.ipv4.conf.all.accept_redirects sysctl, though.
#. address space randomination to system
 

##############################################################################################################

# sources to help the script
. libs/helpers.sh #source help

##############################################################################################################

# Installing Dependencies
# Needed Prerequesites will be set up here
install_dep(){
   clear
   n_banner
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m Setting some Prerequisites"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   add-apt-repository universe
   touch /etc/modprobe.d/CIS.conf && chmod 777 /etc/modprobe.d/CIS.conf
   touch /etc/motd && chmod 777 /etc/motd
   touch /etc/securetty && chmod 777 /etc/securetty
   echo "OK Done"
}


##############################################################################################################

# Configure Hostname
config_host() {
clear
n_banner
echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo "\e[93m[+]\e[00m Setting up Hostname"
echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo "" 

    echo -n "¿Do you Wish to Set a HostName? (y/n):" ; read config_host

    case $config_host in

    y | Y | Yes | YES)
        serverip=$(__get_ip)
        echo " Type a Name to Identify this server :"
        echo -n " (For Example: myserver): "; read host_name
        echo -n " ¿Type Domain Name?: "; read domain_name
        echo $host_name > /etc/hostname
        hostname -F /etc/hostname
        echo "127.0.0.1    localhost.localdomain      localhost" >> /etc/hosts
        echo "$serverip    $host_name.$domain_name    $host_name" >> /etc/hosts
        #Creating Legal Banner for unauthorized Access
        echo ""
        echo "Creating legal Banners for unauthorized access"
        cat templates/motd > /etc/motd
        cat templates/motd > /etc/issue
        cat templates/motd > /etc/issue.net
        echo "OK Done"
    ;;

    n | N | No | NO)
        echo "Ok Bye"
    ;;

    esac  
}


##############################################################################################################

# Configure TimeZone
config_timezone(){
   clear
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m We will now Configure the TimeZone"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
}

##############################################################################################################

# Update System, Install sysv-rc-conf tool
update_system(){
   clear
   n_banner
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m Updating the System"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt update
   apt upgrade -y
   apt dist-upgrade -y
}


##############################################################################################################

# Setting a more restrictive UMASK
restrictive_umask(){
   clear
   n_banner
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m Setting UMASK to a more Restrictive Value (027)"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   cp templates/login.defs /etc/login.defs
   echo ""
   echo "OK Done"
}

##############################################################################################################

#Securing /tmp Folder
secure_tmp(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Securing /tmp Folder"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " ¿Did you Create a Separate /tmp partition during the Initial Installation? (y/n): "; read tmp_answer
  if [ "$tmp_answer" == "n" ]; then
      echo "We will create a FileSystem for the /tmp Directory and set Proper Permissions "
      dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000
      mkdir /tmpbackup
      cp -Rpf /tmp /tmpbackup
      mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
      chmod 1777 /tmp
      cp -Rpf /tmpbackup/* /tmp/
      rm -rf /tmpbackup
      echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
      sudo mount -o remount /tmp
  else
      echo "Nice Going, Remember to set proper permissions in /etc/fstab"
      echo ""
      echo "Example:"
      echo ""
      echo "/dev/sda4   /tmp   tmpfs  loop,nosuid,noexec,rw  0 0 "
  fi
}


##############################################################################################################

# Set IPTABLES Rules
set_iptables(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Setting IPTABLE RULES"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Setting Iptables Rules..."
    sh templates/iptables.sh
    cp templates/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
}


##############################################################################################################

# Install fail2ban
    # To Remove a Fail2Ban rule use:
    # iptables -D fail2ban-ssh -s IP -j DROP
install_fail2ban(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Installing Fail2Ban"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    #apt install sendmail
    apt install fail2ban
}



##############################################################################################################

# Tune and Secure Kernel
tune_secure_kernel(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Tuning and Securing the Linux Kernel"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Securing Linux Kernel"
    echo "* hard core 0" >> /etc/security/limits.conf
    cp templates/sysctl.conf /etc/sysctl.conf; echo " OK"
    #cp templates/ufw /etc/default/ufw
    sysctl -e -p
}


##############################################################################################################

# Install RootKit Hunter
install_rootkit_hunter(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Installing RootKit Hunter"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Rootkit Hunter is a scanning tool to ensure you are you're clean of nasty tools. This tool scans for rootkits, backdoors and local exploits by running tests like:

          - MD5 hash compare
          - Look for default files used by rootkits
          - Wrong file permissions for binaries
          - Look for suspected strings in LKM and KLD modules
          - Look for hidden files
          - Optional scan within plaintext and binary files "
    sleep 1
    cd rkhunter-1.4.6/
    sh installer.sh --layout /usr --install
    cd ..
    rkhunter --update
    rkhunter --propupd
    echo ""
    echo " ***To Run RootKit Hunter ***"
    echo "     rkhunter -c --enable all --disable none"
    echo "     Detailed report on /var/log/rkhunter.log"
}


##############################################################################################################

# Add Daily Update Cron Job
daily_update_cronjob(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Adding Daily System Update Cron Job"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Creating Daily Cron Job"
    job="@daily apt update; apt dist-upgrade -y"
    touch job
    echo $job >> job
    crontab job
    rm job
}


##############################################################################################################

# Install PortSentry
install_portsentry(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Installing PortSentry"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install portsentry
    mv /etc/portsentry/portsentry.conf /etc/portsentry/portsentry.conf-original
    cp templates/portsentry /etc/portsentry/portsentry.conf
    sed s/tcp/atcp/g /etc/default/portsentry > cyberphoenix.tmp
    mv cyberphoenix.tmp /etc/default/portsentry
    /etc/init.d/portsentry restart
}


##############################################################################################################

# Install and Configure Artillery
install_artillery (){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Cloning Repo and Installing Artillery"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    git clone https://github.com/BinaryDefense/artillery
    cd artillery/
    python setup.py
    cd ..
    echo ""
    echo "Setting Iptable rules for artillery"
    
    for port in 22 1433 8080 21 5900 53 110 1723 1337 10000 5800 44443 16993; do
      echo "iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT" >> /etc/init.d/iptables.sh
    done
    echo ""
    echo "Artillery configuration file is /var/artillery/config"
      
}



##############################################################################################################

# Additional Hardening Steps
additional_hardening(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Running additional Hardening Steps"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Running Additional Hardening Steps...."
    
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #Remove AT and Restrict Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " Securing Cron "
    
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
    echo -n " Do you want to Disable USB Support for this Server? (y/n): " ; read usb_answer
    if [ "$usb_answer" == "y" ]; then
       echo ""
       echo "Disabling USB Support"
       
       echo "blacklist usb-storage" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u
       echo "OK Done"
       
    else
       echo "OK Done"
       
    fi
}


##############################################################################################################

# Install Unhide
install_unhide(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Installing UnHide"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs or by another hidden technique."
    sleep 1
    apt -y install unhide
    echo ""
    echo " Unhide is a tool for Detecting Hidden Processes "
    echo " For more info about the Tool use the manpages "
    echo " man unhide "
    
}



##############################################################################################################

# Install Tiger
#Tiger is and Auditing and Intrusion Detection System
install_tiger(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Installing Tiger"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Tiger is a security tool that can be use both as a security audit and intrusion detection system"
    sleep 1
    apt -y install tiger
    echo ""
    echo " For More info about the Tool use the ManPages "
    echo " man tiger "
    
}


##############################################################################################################


# Disable Compilers
disable_compilers(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Disabling Compilers"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Disabling Compilers....."
    
    chmod 000 /usr/bin/as >/dev/null 2>&1
    chmod 000 /usr/bin/byacc >/dev/null 2>&1
    chmod 000 /usr/bin/yacc >/dev/null 2>&1
    chmod 000 /usr/bin/bcc >/dev/null 2>&1
    chmod 000 /usr/bin/kgcc >/dev/null 2>&1
    chmod 000 /usr/bin/cc >/dev/null 2>&1
    chmod 000 /usr/bin/gcc >/dev/null 2>&1
    chmod 000 /usr/bin/*c++ >/dev/null 2>&1
    chmod 000 /usr/bin/*g++ >/dev/null 2>&1
    
    echo ""
    echo " If you wish to use them, just change the Permissions"
    echo " Example: chmod 755 /usr/bin/gcc "
    echo " OK"
    
}



##############################################################################################################

# Additional Security Configurations
#Enable Unattended Security Updates
unattended_upgrades(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Enable Unattended Security Updates"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n " ¿Do you Wish to Enable Unattended Security Updates? (y/n): "; read unattended
  if [ "$unattended" == "y" ]; then
      dpkg-reconfigure -plow unattended-upgrades
  else
      clear
  fi
}


##############################################################################################################

# Enable Process Accounting
enable_proc_acct(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Enable Process Accounting"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install acct
  touch /var/log/wtmp
  echo "OK Done"
}


##############################################################################################################

#Install and enable auditd

install_auditd(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Installing auditd"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install auditd

  # Using CIS Benchmark configuration

  #Ensure auditing for processes that start prior to auditd is enabled
  echo ""
  echo "Enabling auditing for processes that start prior to auditd"
  
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub

  echo ""
  echo "Configuring Auditd Rules"
  

  cp templates/audit-CIS.rules /etc/audit/rules.d/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/rules.d/audit.rules

  echo " " >> /etc/audit/rules.d/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/rules.d/audit.rules
  echo "-e 2" >>/etc/audit/rules.d/audit.rules

  systemctl enable auditd.service
  service auditd restart
  echo "OK Done"
  
}


##############################################################################################################

#Install and Enable sysstat

install_sysstat(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Installing and enabling sysstat"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install sysstat
  sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
  service sysstat start
  echo "OK Done"
  
}


##############################################################################################################

#Install ArpWatch

install_arpwatch(){
  clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m ArpWatch Install"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "ArpWatch is a tool for monitoring ARP traffic on System. It generates log of observed pairing of IP and MAC."
  echo ""
  echo -n " Do you want to Install ArpWatch on this Server? (y/n): " ; read arp_answer
  if [ "$arp_answer" == "y" ]; then
     echo "Installing ArpWatch"
     
     apt install -y arpwatch
     systemctl enable arpwatch.service
     service arpwatch start
     echo "OK Done"
     
  else
     echo "OK Done"
     
  fi
}


##############################################################################################################

#Install PSAD
#PSAD actively monitors firewall logs to determine if a scan or attack is taking place
install_psad(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Install PSAD"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo " PSAD is a piece of Software that actively monitors you Firewall Logs to Determine if a scan
        or attack event is in Progress. It can alert and Take action to deter the Threat

        NOTE:
        IF YOU ARE ONLY RUNNING THIS FUNCTION, YOU MUST ENABLE LOGGING FOR iptables

        iptables -A INPUT -j LOG
        iptables -A FORWARD -j LOG

        "
    echo ""
    echo -n " Do you want to install PSAD (Recommended)? (y/n): " ; read psad_answer
    if [ "$psad_answer" == "y" ]; then
        echo -n " Type an Email Address to Receive PSAD Alerts: " ; read inbox1
        apt install psad
        sed -i s/INBOX/$inbox1/g templates/psad.conf
        sed -i s/CHANGEME/$host_name.$domain_name/g templates/psad.conf  
        cp templates/psad.conf /etc/psad/psad.conf
        psad --sig-update
        service psad restart
        echo "Installation and Configuration Complete"
        echo "Run service psad status, for detected events"
        echo ""
        
    else
        echo "OK Done"
        
    fi
}


#############################################################################################################

#Disabling Unused Filesystems

unused_filesystems(){
   clear
   n_banner
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m Disabling Unused FileSystems"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
}

##############################################################################################################

uncommon_netprotocols(){
   clear
   n_banner
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo "\e[93m[+]\e[00m Disabling Uncommon Network Protocols"
   echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"

}

##############################################################################################################

file_permissions(){
 clear
  n_banner
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo "\e[93m[+]\e[00m Setting File Permissions on Critical System Files"
  echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  
  sleep 2
  chmod -R g-wx,o-rwx /var/log/*

  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config

  chown root:root /etc/passwd
  chmod 644 /etc/passwd

  chown root:shadow /etc/shadow
  chmod o-rwx,g-wx /etc/shadow

  chown root:root /etc/group
  chmod 644 /etc/group

  chown root:shadow /etc/gshadow
  chmod o-rwx,g-rw /etc/gshadow

  chown root:root /etc/passwd-
  chmod 600 /etc/passwd-

  chown root:root /etc/shadow-
  chmod 600 /etc/shadow-

  chown root:root /etc/group-
  chmod 600 /etc/group-

  chown root:root /etc/gshadow-
  chmod 600 /etc/gshadow-


  echo ""
  echo "Setting Sticky bit on all world-writable directories"
  sleep 2
  

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

  echo " OK"
  

}


##############################################################################################################

# Reboot Server
remove_unwanted(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Removing Unwanted Software"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

    #apt-get remove telnet


}



##############################################################################################################

# Reboot Server
reboot_server(){
    clear
    n_banner
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo "\e[93m[+]\e[00m Final Step"
    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

    echo -n " ¿Were you able to connect via SSH to the Server using your credentials? (y/n): "; read answer
    if [ "$answer" == "y" ]; then
        reboot
    else
        echo "Server will not Reboot"
        echo "Bye."
    fi
}



##############################################################################################################

#Check if Running with root user

if [ "$USER" != "root" ]; then
      clear
      n_banner
      echo "\e[34m ${red}---------------------------------------------------------------------------------------------------------${clear} \e[00m"
      echo "${red}PERMISSION DENIED: Can only be run by root..........${clear}"
      echo "\e[34m ${red}---------------------------------------------------------------------------------------------------------${clear} \e[00m"
      echo ""
      exit 0
else
      clear
      n_banner
      install_dep
      config_host

        #config_timezone
        #update_system
        #restrictive_umask
        #secure_tmp
        #set_iptables
        #tune_secure_kernel
        #install_rootkit_hunter
        #daily_update_cronjob
        #install_portsentry
        #additional_hardening
        #install_unhide
        #install_tiger
        #disable_compilers
        #unattended_upgrades
        #enable_proc_acct
        #install_auditd
        #install_sysstat
        #install_arpwatch
        #install_psad
        #unused_filesystems
        #uncommon_netprotocols        
        #file_permissions
        #reboot_server
fi














































#
#
#
#
#
###############################################################################################################
#
## Configure fail2ban
#config_fail2ban(){
#    clear
#    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#    echo "\e[93m[+]\e[00m Configuring Fail2Ban"
#    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#    echo ""
#    echo " Configuring Fail2Ban......"
#    sed s/MAILTO/$inbox/g templates/fail2ban > /etc/fail2ban/jail.local
#    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.conf
#    /etc/init.d/fail2ban restart
#}
#
#
#
#
###############################################################################################################
#
## Tuning
#tune_nano_vim_bashrc(){
#    clear
#    
#    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#    echo "\e[93m[+]\e[00m Tunning bashrc, nano and Vim"
#    echo "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
#    echo ""
#
## Tune .bashrc
#    echo "Tunning .bashrc......"
#    
#    cp templates/bashrc-root /root/.bashrc
#    cp templates/bashrc-user /home/$username/.bashrc
#    chown $username:$username /home/$username/.bashrc
#    echo "OK Done"
#
#
## Tune Vim
#    echo "Tunning Vim......"
#    
#    tunning vimrc
#    echo "OK Done"
#
#
## Tune Nano
#    echo "Tunning Nano......"
#    
#    tunning nanorc
#    echo "OK Done"
#    
#}


