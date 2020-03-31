#!/bin/bash

ip netns add ns1
ip netns exec ns1 ifconfig lo up

# Create veth link pair
ip link add veth1 type veth peer name vpeer1
# Add peer-1 to NS.
ip link set vpeer1 netns ns1

# Setup IP address of veth1
ip addr add 10.20.1.1/24 dev veth1
ip link set veth1 up

# Setup IP address of vpeer1.
ip netns exec ns1 ip addr add 10.200.1.2/24 dev vpeer1
ip netns exec ns1 ip link set vpeer1 up
ip netns exec ns1 ip link set lo up
