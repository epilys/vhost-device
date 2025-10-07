# vhost-device-media - vhost-user virtio media backend

## Description

## Synopsis

```console
vhost-device-media [OPTIONS]
```

## Options

```text
 vhost-device-media

 -h, --help

  Print help.

 -s, --socket-path=PATH

  Location of vhost-user Unix domain socket. This supports a single socket /
  guest.
```

## Examples

The daemon should be started first:

```console
  host# vhost-device-media --socket-path=vmedia.sock
```

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
