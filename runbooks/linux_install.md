
```
# Download Splunk && the MD5 hash
wget -O splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz "https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz" && wget -O splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz.md5 "https://download.splunk.com/products/splunk/releases/9.0.4.1/linux/splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz.md5"

# Check the MD5 hash
md5sum -c splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz.md5

# Extract Splunk
sudo tar -zxvf splunk-9.0.4.1-419ad9369127-Linux-x86_64.tgz -C /opt/

# Add a splunk user
sudo useradd splunk

# Change ownership of the extracted files
sudo chown -R splunk: /opt/splunk/

# Enable Splunk to start automatically using systemd
sudo /opt/splunk/bin/splunk enable boot-start -user splunk --accept-license -systemd-managed 1

# Update ulimits in unit file
sudo sed -i 's#^LimitNOFILE=65536#LimitNOFILE=65536\nLimitNPROC=20480#' /etc/systemd/system/Splunkd.service

# Create a systemd unit file to disable THP
sudo cat > /etc/systemd/system/disable-thp.service << EOL
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the newly created unit file
sudo systemctl daemon-reload
sudo systemctl enable --now disable-thp


# Open ports as required
sudo firewall-cmd --add-port={443/tcp,8000/tcp,8089/tcp}

# Redirect 443 to 8000 if desired
sudo firewall-cmd --add-forward-port=port=443:proto=tcp:toport=8000

# Save the changes
sudo firewall-cmd --runtime-to-permanent
sudo firewall-cmd --reload


# Overly aggressive reboot will confirm everything works as expected
sudo reboot

# Verify ulimits, and then monitor
sudo grep ulimit /opt/splunk/var/log/splunk/splunkd.log
sudo tail -F /opt/splunk/var/log/splunk/splunkd.log
```
