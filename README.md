# Socket

![license](https://img.shields.io/badge/license-MIT-brightGreen.svg)
[![build](https://github.com/originphp/socket/workflows/CI/badge.svg)](https://github.com/originphp/socket/actions)
[![coverage](https://coveralls.io/repos/github/originphp/socket/badge.svg?branch=master)](https://coveralls.io/github/originphp/socket?branch=master)

The `Socket` class is a lightweight wrapper which makes working with sockets easy.

## Installation

To install this package

```linux
$ composer require originphp/socket
```

## Using Sockets

```php
use Origin\Socket\Socket;
$socket = new Socket([
    'host' => 'localhost',
    'protocol' => 'tcp',
    'port' => 25,
    'timeout' => 30,
    'persistent' => false,
]);

if ($socket->connect()) {
    $socket->write("HELO mydomain.com\r\n");
    $result = $socket->read();
}

$socket->disconnect();
```

You can can also enable encryption using  `ssl` or `tls`, you can also specify versions e.g. `sslv2`, `sslv23`, `sslv3`, `tlsv1`, `tlsv11` and `tlsv12`. See the [PHP manual](https://www.php.net/manual/en/function.stream-socket-enable-crypto.php) for more information on the encryption methods.

To enable encryption

```php
$socket->enableEncryption('tls');
$socket->enableEncryption('ssl');
```

To disable encryption

```php
$socket->disableEncryption('tls');
$socket->disableEncryption('ssl');
```

## Host/IP Address

To get the IP address of the connection

```php
$ipAddress = $socket->address();
```

To get the hostname

```php
$hostname = $socket->host();
```

## Stream Contexts

When creating a Socket you can also provide `context` options that will be used to create a [stream context](https://www.php.net/manual/en/function.stream-context-create.php).

```php
$socket = new Socket([
    'host' => 'example.com',
    'protocol' => 'tcp',
    'port' => 443,
    'timeout' => 30,
    'persistent' => false,
    'context' => [
        'ssl' => [
            'verify_peer' => false
        ]
    ]
]);
```