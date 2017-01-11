# Collectd plugin for BIRD

This plugin will collectd various metrics from BIRD. It collects:

 - memory stats
 - BFD sessions
 - BGP sessions
 - route stats

## Installation

The plugin should be copied in `/usr/share/collectd/python/` or
another place specified by `ModulePath` in the Python plugin
configuration. The `types.bird.db` file also needs to be copied in
`/usr/share/collectd/` and registered with `TypesDB`.

## Configuration

This should be used like this:

    LoadPlugin python
    TypesDB "/usr/share/collectd/types.bird.db"

    <Plugin python>
      ModulePath "/usr/share/collectd/python"
      Import "bird"
      <Module bird>
        socket "/var/run/bird/bird.ctl"
        instance "v4"
      </Module>
    </Plugin>

Only the configuration keys exposed in the example are valid. Their
default values are the ones in the example.

## BIRD configuration

It is required to use the following configuration settings to get
proper dates from BIRD:

    timeformat route iso long;
    timeformat protocol iso long;

# Testing

A one-time collection can be triggered with:

    collectd -C collectd.conf -T
