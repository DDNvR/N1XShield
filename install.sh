#!/bin/bash

# N1XShield v1.0
# Unix / Linux System Hardening Script
# Currenct OS Supported
# ------ Updated: 23.04 ("Lunar Lobster")

. libs/helpers.sh #source help

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
    echo "\e[34m ${green}---------------------------------------------------------------------------------------------------------${clear} \e[00m"
    echo "\e[93m[+]\e[00m ${green}SELECT YOUR LINUX DISTRIBUTION ${clear}"
    echo "\e[34m ${green}---------------------------------------------------------------------------------------------------------${clear} \e[00m"
    echo ""
    echo "1. Ubuntu > 22.04+"
    echo "0. Exit"
    echo
    echo "\e[34m ${green}---------------------------------------------------------------------------------------------------------${clear} \e[00m"
    echo

    echo -n "Enter your Selection:" ; read MENU

    case $MENU in

    1)
        chmod +x ubuntu/ubuntu_install.sh && sh ubuntu/ubuntu_install.sh
        ;;

    0)
        break
        ;;

    *)
        clear
        sh install.sh    
        ;;
    esac

fi

##############################################################################################################

