# Automated Deployment of Windows Virtual Desktop

This repo is comprised of a PowerShell module (Az.WvdOperations), Azure ARM templates, Azure ARM template parameter files and Desired State Configuration scripts.  The goal of this repo is to provide any organization looking to deploy Windows Virtual Desktop, an easy to use deployment model based on a set group of standards.

> **WARNING:**
> 
> This repo assumes that you or your organization are already well established into Microsoft Azure. There are many dependancies required to make this repo / solution to work correctly. The requirements section below should outline what is required for this repo to be successfully deployed.

---

## Table of Contents

- [Requirements](Docs/Requirements.md)
  - [Knowledge](Docs/Requirements.md#knowledge)
  - [Azure](Docs/Requirements.md#azure)
  - [Non-Azure](Docs/Requirements.md#non-azure)
- [Azure Greenfield Setup](Docs/Azure-Greenfiled-Setup.md)
- [Post Setup Configuration](Docs/Post-Setup-Configuration.md)
- [Getting Started](docs/Getting-Started.md)

---

## Architecture Example (my personal lab)

![WVD-Architecture](/Docs/_media/WVD-Architecture.png)