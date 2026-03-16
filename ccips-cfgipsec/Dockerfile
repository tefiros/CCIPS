# © 2026 Telefónica Innovación Digital 
# (mattinantartiko.elorzaforcada@telefonica.com)
# (victor.hernandofernandez@telefonica.com)

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM sysrepo/sysrepo-netopeer2

RUN apt update && apt install -y libpthread-stubs0-dev

# Setup netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo;

ADD . /cfgipsec2
WORKDIR /cfgipsec2

# Install yang models
RUN sysrepoctl -i yang/ietf-inet-types.yang  --permissions=666 -v3 && \ 
sysrepoctl -i yang/ietf-netconf-acm.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-yang-types.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-i2nsf-ikec.yang  --permissions=666 -v3 && \
sysrepoctl -i yang/ietf-i2nsf-ikeless.yang  --permissions=666 -v3

RUN sysrepoctl -c ietf-i2nsf-ikeless -e ikeless-notification  -v3

RUN rm -rf parson && git clone https://github.com/kgabis/parson
RUN mkdir -p build && cd build && rm -rf * &&  cmake  .. && make

ADD supervisord.conf /etc/supervisord.conf

RUN echo '<nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm"><enable-nacm>false</enable-nacm></nacm>' > /disable-acm.xml
RUN sysrepocfg --import=/disable-acm.xml -f xml --datastore startup --module ietf-netconf-acm -v3 && \
sysrepocfg --import=/disable-acm.xml -f xml --datastore running --module ietf-netconf-acm -v3 
