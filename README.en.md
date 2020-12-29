# openGauss-OM

#### Description
Operation Manager provides management interfaces and tools for opengauss routine O&M and  configuration management.
Common functions include database installtion, startup, stop, upgrade, backup, status query, and log collection.

#### Compilation

- See the compilation description of the [opengauss third-party-software](https://gitee.com/opengauss/openGauss-server/blob/master/README.en.md#compiling-third-party-software)。                     
  The final compilation and build result is stored in the binarylibs directory at the same level as openGauss-third_party.                
  The binarylibs directory will be the value of '-3rd' for build.sh                  
- ./build.sh -3rd ${BINARYLIBS_PATH}              
  The generated installation package is stored in the ./package directory:                 
  openGauss-1.1.0-CentOS-64bit-om.sha256               
  openGauss-1.1.0-CentOS-64bit-om.tar.gz              
   
#### Installation

The OM tool strongly depends on opengaussServer. Please see the [opengauss Installation](https://opengauss.org/zh/docs/latest/docs/installation/installation.html)。

## Quick Start

See the [Quick Start](https://opengauss.org/en/docs/1.0.1/docs/Quickstart/Quickstart.html).

## Docs

For more details about the installation guide, tutorials, and APIs, please see the [User Documentation](https://gitee.com/opengauss/docs).

## Community

### Governance

Check out how openGauss implements open governance [works](https://gitee.com/opengauss/community/blob/master/governance.md).

### Communication

- WeLink- Communication platform for developers.
- IRC channel at `#opengauss-meeting` (only for meeting minutes logging purpose)
- Mailing-list: https://opengauss.org/en/community/onlineCommunication.html

## Contribution

Welcome contributions. See our [Contributor](https://opengauss.org/en/contribution.html) for more details.

## Release Notes

For the release notes, see our [RELEASE](https://opengauss.org/en/docs/1.0.1/docs/Releasenotes/Releasenotes.html).

## License

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2/)