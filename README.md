# Dynamic WFP Filters Generator

<div align="center">
  <img src="logo.PNG" width="450">
</div>
<br>

Custom implementation of the Windows Filtering Platform (WFP), designed to provide fine-grained control over network traffic at the system level. This tool allows managing network traffic rules using Windows Filtering Platform (WFP), it can permit or block traffic for a specified CIDR range.
Makes easy Permit/Block IPv4 CIDR in Windows Filtering Platform using low level system calls. 

### Installation
- Requires Go and Windows administrator privileges.
- Compile the program: `go build -o firewall_tool.exe`.

### Usage
```sh
firewall_tool.exe [-permit|-block] CIDR
```
- `-permit` → Allows traffic for the given CIDR.
- `-block` → Blocks traffic for the given CIDR.
- `CIDR` → Network range in CIDR notation.

### Behavior
- Ensures only one flag is used.
- Establishes a WFP session and registers necessary objects.
- Applies the specified rule.
- Runs until terminated manually.

### Stopping the Program
Use `Ctrl+C` or send a termination signal to remove rules and exit.




