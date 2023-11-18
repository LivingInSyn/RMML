# RMML
RMML is the Remote Management and Monitoring (tool) List. It is a list of RMM tools with associated metadata that aims to be useful for IT and Security teams.

The use case this was created for is a security team who wants to monitor their environment for RMMs that aren't supposed to be there (or for all of them). CI in the releases will include the contents of the `RMMs` folder in forms designed to be consumed by various EDRs and alerting mechanisms. It is released in the complete form as well as with incividual exclusions for easy exclusion of your RMM of choice.

Currently supported CI integrations are:

* Carbon Black

**PRs are welcome and encouraged!**

## Desired Definitions
If you're looking to make a PR, the following is a list of desired definitions:

- ~~zoho assist~~ (PR: #10)
- ~~splashtop~~
- ~~ScreenConnect~~ (PR: 9, thanks to @signifi3d)
- Remote Utilities
- AnyConnect
- Chrome Remote Desktop
- ~~Rustdesk~~ (PR: #1)

## Using it:
Carbon Black: see the CarbonBlack directory

## Schema
New RMMs should be added as a new file in the `RMMs` directory.

Each new RMM should be in the format:

Note that executables are assumed to have a wildcard to start the path. so `baz/bar` will be assumed to match `/baz/bar` and `/some/path/baz/bar`

```yaml
Executables:
    SignerSubjectName: <code signing subject name> (mostly useful for Windows and *nix)
    MacOSSigner: <MacOS code signing name>
    Windows:
        - list 
        - of
        - executables
    MacOS:
        - list 
        - of
        - executables
    Linux:
        - list 
        - of
        - executables
NetConn:
    Domains:
        - domains
        - "*.wilcards.allowed"
    Ports:
        - 443
        - 8080
```

Example (from `./RMMs/TeamViewer.yml`):

```yaml
Executables:
  SignerSubjectName: TeamViewer GmbH
  MacOSSigner:
  Windows:
  - TeamViewer.exe
  - TeamViewer_Setup.exe
  MacOS:
  - TeamViewer
  Linux:
  - TeamViewer
NetConn:
  Domains:
  - '*.teamviewer.com'
  Ports:
  - 5938
```

A blank to make life easy for creating PRs:

```yaml
Executables:
  SignerSubjectName:
  MacOSSigner:
  Windows:
    - 
  MacOS:
    - 
  Linux:
    - 
NetConn:
  Domains:
    - 
  Ports:
    - 443
```
