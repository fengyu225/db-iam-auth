#!/bin/bash

set -e

echo "Starting Elasticsearch setup..."

echo "Updating system packages..."
sudo yum update -y

echo "Installing Java 11 Amazon Corretto..."
sudo yum install java-11-amazon-corretto-headless -y

echo "Verifying Java installation..."
java -version

echo "Importing Elasticsearch GPG key..."
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

echo "Creating Elasticsearch repository configuration..."
sudo tee /etc/yum.repos.d/elasticsearch.repo > /dev/null <<EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF

echo "Installing Elasticsearch..."
sudo yum install --enablerepo=elasticsearch elasticsearch -y

echo "Backing up original Elasticsearch configuration..."
sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.backup

echo "Creating Elasticsearch configuration..."
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
cluster.name: my-cluster
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Security settings (disabled initially)
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF

# Enable and start Elasticsearch service
echo "Enabling and starting Elasticsearch service..."
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

echo "Checking Elasticsearch status..."
sudo systemctl status elasticsearch --no-pager

# Test Elasticsearch connection
echo "Testing Elasticsearch connection..."
if curl -s http://localhost:9200 > /dev/null; then
    echo "✅ Elasticsearch is running successfully!"
    curl -s http://localhost:9200 | jq . 2>/dev/null || curl -s http://localhost:9200
else
    echo "❌ Elasticsearch is not responding on port 9200"
    echo "Check the logs with: sudo journalctl -u elasticsearch"
    exit 1
fi

echo ""
echo "Elasticsearch setup completed successfully!"
echo ""