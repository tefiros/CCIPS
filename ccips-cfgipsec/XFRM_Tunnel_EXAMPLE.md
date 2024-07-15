
# Scenario

[![I2-NSF-OPo-T-transport-mode-drawio.png](https://i.postimg.cc/7hNscWv9/I2-NSF-OPo-T-transport-mode-drawio.png)](https://postimg.cc/Mfvmftpf)

# Commands to execute

This commands must be executed as root user.

```bash
// To execute in Computer1 192.168.165.169
export SPI=0x69427567
export AUTHKEY=0x0123456789ABCDEF0123456789ABCDEF
export ENCKEY=0xFEDCBA9876543210FEDCBA9876543210
export NET_INTERNAL_HOST=192.168.100.0/24
export NET_INTERNAL_OTHER_HOST=192.168.200.0/24
export IP_DATA_HOST=192.168.165.169
export IP_DATA_OTHER_HOST=192.168.165.93 

ip xfrm policy add src $NET_INTERNAL_HOST dst $NET_INTERNAL_OTHER_HOST  dir out tmpl src $IP_DATA_HOST dst $IP_DATA_OTHER_HOST proto esp spi $SPI mode tunnel
ip xfrm policy add src $NET_INTERNAL_OTHER_HOST dst $NET_INTERNAL_HOST  dir in tmpl src $IP_DATA_OTHER_HOST dst $IP_DATA_HOST proto esp spi $SPI mode tunnel
ip xfrm state add src $IP_DATA_HOST dst $IP_DATA_OTHER_HOST proto esp spi $SPI mode tunnel auth sha256 $AUTHKEY enc aes $ENCKEY
ip xfrm state add src $IP_DATA_OTHER_HOST dst $IP_DATA_HOST  proto esp spi $SPI mode tunnel auth sha256 $AUTHKEY enc aes $ENCKEY
```

```bash
// To execute in Computer2 192.168.165.93
export SPI=0x69427567
export AUTHKEY=0x0123456789ABCDEF0123456789ABCDEF
export ENCKEY=0xFEDCBA9876543210FEDCBA9876543210
export NET_INTERNAL_HOST=192.168.200.0/24
export NET_INTERNAL_OTHER_HOST=192.168.100.0/24
export IP_DATA_HOST=192.168.165.93
export IP_DATA_OTHER_HOST=192.168.165.169 


ip xfrm policy add src $NET_INTERNAL_HOST dst $NET_INTERNAL_OTHER_HOST  dir in tmpl src $IP_DATA_OTHER_HOST dst $IP_DATA_HOST proto esp spi $SPI mode tunnel
ip xfrm policy add src $NET_INTERNAL_OTHER_HOST dst $NET_INTERNAL_HOST  dir out tmpl src $IP_DATA_HOST dst $IP_DATA_OTHER_HOST proto esp spi $SPI mode tunnel
ip xfrm state add src $IP_DATA_OTHER_HOST dst $IP_DATA_HOST proto esp spi $SPI mode tunnel auth sha256 $AUTHKEY enc aes $ENCKEY
ip xfrm state add src $IP_DATA_HOST dst $IP_DATA_OTHER_HOST  proto esp spi $SPI mode tunnel auth sha256 $AUTHKEY enc aes $ENCKEY
```

Once the commands are executed you can ping from Computer1 `192.168.165.169` to Computer2 `192.168.165.93` using IPsec in transport mode.  