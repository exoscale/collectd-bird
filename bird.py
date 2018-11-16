#!/usr/bin/env python

"""Collectd module to extract statistics from a running BIRD daemon."""

from __future__ import print_function
from __future__ import unicode_literals

import sys
import re
from datetime import datetime
import time
import socket
import collectd


def uptime(since):
    """Turn an date and time into an uptime value.

    The returned value is a number of seconds from the provided value
    to the current time. The date/time provided is expected to be a
    local time using the following format: 2017-01-10 16:32:21.

    """
    fr = datetime(*time.strptime(since, "%Y-%m-%d %H:%M:%S")[:6])
    to = datetime.now()
    delta = to - fr
    delta = int(delta.total_seconds())
    if delta < 0:
        return 0
    return delta


class Bird(object):

    """Extract information from BIRD using Unix socket."""

    re_memory = re.compile(r"(?P<attribute>.*):\s+"
                           r"(?P<quantity>\d+)\s"
                           r"(?P<multiplier>[kMG ])B\s*")
    re_bfd = re.compile(r"(?P<ip>[0-9af:.]+)\s+"
                        r"(?P<interface>\S+)\s+"
                        r"(?P<state>\S+)\s+"
                        r"(?P<since>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
                        r"(?P<interval>\d+\.\d+)\s+"
                        r"(?P<timeout>\d+\.\d+)")
    re_protocol = re.compile(r"(?P<name>\S+)\s+"
                             r"(?P<protocol>\S+)\s+"
                             r"(?P<table>\S+)\s+"
                             r"(?P<state>\S+)\s+"
                             r"(?P<since>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
                             r"(?:$|\s+.*)")
    re_bgp = re.compile(r"\s+(?P<label>[^:]+):\s+(?P<value>.*)")
    re_bgp_routes = re.compile(r"(?P<imported>\d+) imported, "
                               r"(?P<exported>\d+) exported, "
                               r"(?P<preferred>\d+) preferred")

    def __init__(self, socket="/var/run/bird/bird.ctl"):
        self.socket = socket

    def get_memory(self):
        """Return memory information about BIRD.

        This returns a dictionary of attributes with their associated
        sizes in bytes.

        """
        data = self._query("show memory", ["1018"])
        results = {}
        for line in data:
            mo = self.re_memory.match(line)
            if mo:
                quantity = int(mo.group("quantity"))
                for m in " kMG":
                    if mo.group("multiplier") == m:
                        break
                    quantity *= 1024
                results[mo.group("attribute").lower()] = quantity
        return results

    def get_bfd(self):
        """Return BFD information from BIRD.

        This returns a dictionary of BFD instances. Each instance is a
        list of BFD sessions. A session is a dictionary with IP,
        interface, state, uptime (in seconds), interval and
        timeout. It should be noted that the same IP can appear
        several times.
        """
        data = self._query("show bfd sessions", ["1020"])
        if len(data) == 0:
            return {}

        # Only one BFD protocol is allowed. The first line is protocol
        # name, then the table header, then the table.
        states = {"up": 1,
                  "down": 2,
                  "admindown": 3,
                  "init": 2}    # See RFC 7331
        results = []
        protoname = data[0].rstrip(":")
        data = data[1:]
        for line in data:
            mo = self.re_bfd.match(line)
            if mo:
                results.append(dict(ip=mo.group("ip"),
                                    interface=mo.group("interface"),
                                    state=states.get(
                                        mo.group("state").lower(), 0),
                                    uptime=uptime(mo.group("since")),
                                    interval=float(mo.group("interval")),
                                    timeout=float(mo.group("timeout"))))
        return {protoname: results}

    def get_routes(self):
        """Return route count for each routing table."""
        data = self._query("show symbols table", ["1010"])
        if len(data) == 0:
            return {}

        tables = [re.split(r'\s+', v)[0] for v in data]
        collectd.debug("routes: routing tables: {}".format(tables))

        results = {}
        for t in tables:
            data = self._query("show route table {} count".format(t),
                               ["0014"])
            count = int(re.split(r"\s+", data[0])[0])
            results[t] = count

        return results

    def get_bgp(self):
        """Return BGP related information."""
        s = 0
        data = self._query("show protocols all", ["1002", "1006"])

        states = {"idle": 1,
                  "connect": 2,
                  "active": 3,
                  "opensent": 4,
                  "openconfirm": 5,
                  "established": 6,
                  "close": 7}  # See RFC4273
        results = {}
        current = {}
        for line in data:
            mo = self.re_protocol.match(line)
            if mo:
                if mo.group("protocol") == "BGP":
                    name = mo.group("name")
                    collectd.debug("bgp: BGP protocol {} found".format(name))
                    current = dict(uptime=uptime(mo.group("since")))
                    results[name] = current
                    s = 1
                else:
                    s = 2
                continue
            if s in (0, 2):
                continue
            elif s == 1:
                mo = self.re_bgp.match(line)
                if not mo:
                    continue
                label = mo.group("label").lower()
                value = mo.group("value")
                if label == "routes":
                    mo = self.re_bgp_routes.match(value)
                    if not mo:
                        continue
                    for k in mo.groupdict():
                        current[k] = int(mo.group(k))
                elif label == "bgp state":
                    current["state"] = states.get(value.lower(), 0)
                elif label == "hold timer":
                    a, _, b = value.partition("/")
                    current["hold"] = int(a)
                    current["hold-configured"] = int(b)
                elif label == "keepalive timer":
                    a, _, b = value.partition("/")
                    current["keep"] = int(a)
                    current["keep-configured"] = int(b)
        return results

    def _query(self, query, codes):
        collectd.debug("query: connecting to BIRD with "
                       "socket {}".format(self.socket))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket)
        if sys.version_info >= (3, 0):
            sock = sock.makefile(encoding='ascii')
        else:
            sock = sock.makefile()

        collectd.debug("query: wait for banner")
        line = sock.readline()
        if not line.startswith("0001 "):
            raise RuntimeError("query: expected a banner")

        collectd.debug("query: switch to restricted mode")
        sock.write("restrict\n")
        sock.flush()
        line = sock.readline()
        if not line.startswith("0016 "):
            collectd.debug("query: cannot switch to restricted mode")

        # Send the query
        collectd.debug("query: send {}".format(query))
        sock.write("{}\n".format(query))
        sock.flush()

        # Parse the answer. We assume that we will always get data
        # except when getting 9001. We ignore the continuation rule
        # but enforce the use of a single code.
        data = []
        for line in sock:
            line = line.rstrip()
            if line == "":
                continue
            collectd.debug("query: got {}".format(line))
            if line == "0000":
                break
            if line.startswith(" "):
                data.append(line[1:])
            elif line == "9001 There is no BFD protocol running":
                # 9001 is parse error, but is also used for this kind of error.
                break
            elif ((line[:4] in codes or
                   line[:1] == "2" and
                   line[1:4] in [c[1:4] for c in codes]) and
                  line[4:5] in (" ", "-")):
                data.append(line[5:])
                if line[4] == " ":
                    break
            else:
                raise RuntimeError("query: invalid code {}".format(line[:5]))
        return data


class BirdCollectdInstance(object):

    socket = "/var/run/bird/bird.ctl"
    instance = "v4"

    def configure(self, conf, **kwargs):

        """Collectd configuration callback."""
        if conf is not None:
            kwargs.update({node.key.lower(): node.values
                           for node in conf.children})
        for keyword in kwargs:
            if not isinstance(kwargs[keyword], (list, tuple)):
                kwargs[keyword] = [kwargs[keyword]]
            if keyword == "socket":
                if len(kwargs[keyword]) != 1:
                    raise ValueError("config: socket expects exactly "
                                     "one argument")
                self.socket = kwargs[keyword][0]
            elif keyword == "instance":
                if len(kwargs[keyword]) != 1:
                    raise ValueError("config: instance expects exactly "
                                     "one argument")
                self.instance = kwargs[keyword][0]
            else:
                raise ValueError("config: unknown keyword "
                                 "`{}`".format(keyword))

    def init(self):
        """Collectd init callback."""
        self.bird = Bird(self.socket)

    def dispatch(self, values, type, type_instance):
        """Dispatch a value to collectd."""
        if values is None or any([v is None for v in values]):
            return
        metric = collectd.Values(values=values,
                                 plugin="bird",
                                 plugin_instance=self.instance,
                                 type=type,
                                 type_instance=type_instance)
        metric.dispatch()

    def read(self):
        """Collectd read callback."""
        # Memory
        memory = self.bird.get_memory()
        for k in memory:
            self.dispatch([memory[k]],
                          "memory",
                          k.replace(" ", "-"))
        # BFD
        bfd = self.bird.get_bfd()
        for k in bfd:
            for e in bfd[k]:
                # We may overwrite identical values of protocol/ip/iface.
                instance = "{}-{}-{}".format(k, e["ip"], e["interface"])
                self.dispatch([e["state"],
                               e["uptime"],
                               e["interval"],
                               e["timeout"]],
                              "bird_bfd", instance)

        # Routes
        routes = self.bird.get_routes()
        for t in routes:
            self.dispatch([routes[t]], "bird_table", t)

        # BGP
        bgp = self.bird.get_bgp()
        for p in bgp:
            self.dispatch([bgp[p].get("state", 0),
                           bgp[p].get("uptime", 0),
                           bgp[p].get("hold", 0),
                           bgp[p].get("hold-configured", 0),
                           bgp[p].get("keep", 0),
                           bgp[p].get("keep-configured", 0),
                           bgp[p].get("imported", 0),
                           bgp[p].get("exported", 0),
                           bgp[p].get("preferred", 0)],
                          "bird_bgp", p)


class BirdCollectd(object):

    def __init__(self):
        self.instances = []

    def configure(self, conf, **kwargs):
        print("hello")
        for node in conf.children:
            instance = BirdCollectdInstance()
            instance.configure(node, **kwargs)
            self.instances.append(instance)
        print(self.instances)

    def init(self):
        if not self.instances:
            self.instances = [BirdCollectdInstance()]
        for instance in self.instances:
            instance.init()

    def read(self):
        for instance in self.instances:
            instance.read()


bird = BirdCollectd()
collectd.register_config(bird.configure)
collectd.register_init(bird.init)
collectd.register_read(bird.read)
