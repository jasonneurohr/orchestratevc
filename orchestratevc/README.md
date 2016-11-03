# orchestratevc

# Example Acano/CMS Usage:

**Setting properties for all callLegProfiles:**

```python
    cms = orchestratevc.CiscoMS(api_host="x.x.x.x", api_port="445", api_pass="password")
    cms.set_all_calllegprofile_properties(
        {
            "muteOthersAllowed": "true",
            "changeJoinAudioMuteOverrideAllowed": "true"
        })
```

# Example Supervisor Usage

**Export Supervisor Configuration:**

```python
    supervisor = CiscoMSESupervisor(api_host="x.x.x.x", api_port="445", api_pass="password")
    conf = supervisor.export_config()

    filename = 'C:\\some\\directory\\' + 'serial_' + str(
        datetime.now().strftime("%Y%m%d")) + '.xml'

    fh = open(filename, 'w')
    for line in conf:
        fh.write(line.strip('\r'))
    fh.close()
```

# Example TPS Usage

**Export TPS Configuration:**

```python
    tps = CiscoTPS(api_host='x.x.x.x', api_pass='password')
    conf = tps.export_config()

    filename = 'C:\\some\\directory\\' + 'serial_' + str(
        datetime.now().strftime("%Y%m%d")) + '.xml'

    fh = open(filename, 'w')
    for line in conf:
        fh.write(line.strip('\r'))
```

**Enumerating CDRs**

```python
    tps = orchestratevc.CiscoTPS(api_host='x.x.x.x', api_pass='password')
    tps.get_cdrs()

    for cdr in tps.cdr_jar:
        print(cdr)
```

# Example VCS/Expressway Usage

**Export VCS/Expressway Configuration:**

```python
    vcs = CiscoExp(api_host='x.x.x.x', api_pass='password')
    conf = vcs.export_xconf()

    filename = 'C:\\some\\directory\\' + 'serial_' + str(
        datetime.now().strftime("%Y%m%d")) + '.txt'

    fh = open(filename, 'w')
    fh.write(conf)
    fh.close()
```

# Example ISDN Usage

**Export ISDN GW Configuration:**

```python
    isdngw1 = CiscoISDN(api_host='x.x.x.x', api_pass='password')
    conf = isdngw1.export_config()

    filename = 'C:\\some\\directory\\' + 'serial_' + str(
        datetime.now().strftime("%Y%m%d")) + '.xml'

    fh = open(filename, 'w')
    for line in conf:
        fh.write(line.strip('\r'))
    fh.close()
```