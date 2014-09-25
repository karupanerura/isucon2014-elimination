# libevent
setup/setup-libevent.sh をrootまたはsudo権限があるユーザーで実行する。  
バージョンはshell script内に記載。

# pcre
setup/setup-pcre.sh をrootまたはsudo権限があるユーザーで実行する。  
バージョンはshell script内に記載。

# redis
setup/setup-redis.sh をrootまたはsudo権限があるユーザーで実行する。  
バージョンはshell script内に記載。

# nginx
setup/setup-nginx.sh をrootまたはsudo権限があるユーザーで実行する。  
デフォルトでSSL、Stub、Gzip static、PCRE Jitが使える。  
バージョンはshell script内に記載。

# memcached
libeventを先にインストールする。  
setup/setup-memcached.sh をrootまたはsudo権限があるユーザーで実行する。  
バージョンはshell script内に記載。

# mysql-build
めんどいのでrootに入れてしまえ。

```sh
git clone git://github.com/kamipo/mysql-build.git $HOME/.mysql-build
```

## 使えそうなplugin

オーバーヘッドやバグなどのリスクを考慮して必要最小限のものだけ入れること。
ぶっちゃけ`mysql-build --plugins`で見れる。

* handlersocket-1.1.1
* q4m-master
* mroonga-4.05
* innodb-memcached

## e.g.) mysql 5.6.20
```sh
$HOME/.mysql-build/bin/mysql-build 5.6.20 /opt/mysql/5.6
```

## e.g.) mysql 5.6.20 && handlersocket-1.1.1
```sh
$HOME/.mysql-build/bin/mysql-build 5.6.20 /opt/mysql/5.6 handlersocket-1.1.1
```

## e.g.) mysql 5.6.20 && handlersocket-1.1.1 q4m-master
```sh
$HOME/.mysql-build/bin/mysql-build 5.6.20 /opt/mysql/5.6 handlersocket-1.1.1 q4m-master
```
