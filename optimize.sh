sudo journalctl --vacuum-size=300M # reduces the logs to 300 MB
sudo logrotate /etc/logrotate.conf # deletes system logs
sudo apt-get autoremove # removes software that are only dependencies to packages you removed earlier and don't need anymore
sudo apt-get clean # this is nearly the same as sudo rm -rf /var/cache/apt/archives/* and deletes cached downloaded packages for installation. Running this during some installations could be a problem.
sudo find / -mount -type f -size +100M -exec du -h {} \; | sort -n # Identifying largest file
