# RMML
RMML is the Remote Management and Monitoring (tool) List. It is a list of RMM tools with associated metadata that aims to be useful for IT and Security teams.

The use case this was created for is a security team who wants to monitor their environment for RMMs that aren't supposed to be there. They can use this list (commenting out their RMM of choice) to build alerts.

**PRs are welcome and encouraged!**

## Plans for this repo
The plan for this repo is to build CI steps that will output alerts useful in various tools such as CarbonBlack, SIEMs of various flavors, Sigma alerts, etc

## Schema
New RMMs should be added to the top level `RMM` object in `rmm.yml`

Each new RMM should be in the format:

```yaml
RMM_Name:
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

Example:

```yaml
TeamViewer:
    Executables:
      SignerSubjectName: TeamViewer GmbH
      MacOSSigner:
      Windows:
        - "TeamViewer.exe"
        - "TeamViewer_Setup.exe"
      MacOS:
        - "TeamViewer"
      Linux:
        - "TeamViewer"
    NetConn:
      Domains:
        - "*.teamviewer.com"
      Ports:
        - 5938
```
