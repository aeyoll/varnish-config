varnish-config
==============

## Varnish installation


```
sudo curl http://repo.varnish-cache.org/debian/GPG-key.txt | apt-key add -
sudo echo "deb http://repo.varnish-cache.org/debian/ $(lsb_release -s -c) varnish-2.1" >> /etc/apt/sources.list
sudo apt-get update
sudo apt-get install varnish
```

## References 

* Tutorial: Setting up Varnish with Apache: http://www.euperia.com/website-performance-2/setting-up-varnish-with-apache-tutorial/299
* Putting Varnish In Front Of Apache On Ubuntu/Debian: http://www.howtoforge.com/putting-varnish-in-front-of-apache-on-ubuntu-debian
* Upgrading from Varnish 2.1 to 3.0: https://www.varnish-cache.org/docs/3.0/installation/upgrade.html