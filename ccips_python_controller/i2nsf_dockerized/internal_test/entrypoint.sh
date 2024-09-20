#!/bin/bash
ip r d default
ip r a default via 192.168.2.100
ip r a default via 192.168.1.100
sleep infinity