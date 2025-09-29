#!/bin/bash
# generate_traffic.sh - Script to generate various network traffic for Wireshark capture

echo "🚀 Generating Network Traffic for Wireshark Analysis"
echo "================================================="

echo "📡 Starting ICMP traffic (ping)..."
ping -c 4 google.com &
ping -c 4 8.8.8.8 &
ping -c 4 1.1.1.1 &

echo "🌐 Generating DNS traffic..."
nslookup google.com >/dev/null 2>&1 &
nslookup github.com >/dev/null 2>&1 &
nslookup stackoverflow.com >/dev/null 2>&1 &
dig google.com >/dev/null 2>&1 &

echo "🔗 Creating HTTP traffic..."
curl -s http://httpbin.org/get >/dev/null 2>&1 &
curl -s -I http://example.com >/dev/null 2>&1 &
curl -s http://httpbin.org/user-agent >/dev/null 2>&1 &

echo "🔒 Creating HTTPS traffic..."
curl -s https://httpbin.org/get >/dev/null 2>&1 &
curl -s https://api.github.com/users/octocat >/dev/null 2>&1 &
curl -s https://jsonplaceholder.typicode.com/posts/1 >/dev/null 2>&1 &

echo "🕐 Creating additional protocols..."
# Generate some UDP traffic
nc -u 8.8.8.8 53 <<<'test' >/dev/null 2>&1 &

echo "⏳ Waiting for traffic generation to complete..."
sleep 5
wait

echo "✅ Traffic generation completed!"
echo "🔍 You should now see various protocols in Wireshark:"
echo "   - ICMP (ping packets)"
echo "   - DNS (domain resolution)"  
echo "   - HTTP (web requests)"
echo "   - HTTPS/TLS (secure web requests)"
echo "   - TCP (connection-oriented traffic)"
echo "   - UDP (connectionless traffic)"
echo ""
echo "💡 Now apply these Wireshark filters to analyze:"
echo "   dns     - View DNS queries and responses"
echo "   tcp     - View TCP handshakes and data"
echo "   http    - View HTTP requests and responses"
echo "   icmp    - View ping requests and replies"
echo "   udp     - View UDP traffic"
echo ""
echo "🎯 Happy packet analyzing!"
