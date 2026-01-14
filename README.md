# ICSFieldID
## Introduction
ICSFieldID is a research validation framework for **industrial control protocol field type inference**, using **behavioral features and machine learning**.
It uses protocol packets and binaries as input, extracts program behavior features via symbolic execution, and trains classification models.

## Directory Structure
```aiignore
ICSFieldID
├── analysis.py # Entry point for symbolic execution
├── ast_parser.py # AST Parsing Module
├── bacnet_tracer.py # Submodule for tracing BACnet protocol execution
├── features.csv # Features used in the experiments, divided into three categories
├── mms_tracer.py # Submodule for tracing MMS protocol execution
├── pdml_parser.py # PDML Parsing Module
├── README.md # Project description
├── s7_tracer.py # Submodule for tracing S7COMM protocol execution
├── siblib.py # Common lib for SimProcedure
├── tracer.py # Symbolic execution engine
├── train.py # Model training and evaluation
├── bacserv # Protocol binaries, raw PCAP packets, and PDML-formatted packets for BACnet
├── data # Collected datasets used in experiments
├── mms # Protocol binaries, raw PCAP packets, and PDML-formatted packets for MMS
└── s7 # Protocol binaries, raw PCAP packets, and PDML-formatted packets for S7COMM
```

## Experimental Programs and Features

In our experiments, we used the following client and server programs for each ICS protocol:

| Protocol | Client        | Server         |
|:--------|:-------------|:---------------|
| BACnet  | [YABE](https://github.com/dechamps/yabe)       | [BACnet Stack](https://github.com/bacnet-stack/bacnet-stack) |
| MMS     | [IEDExplorer](https://github.com/rogerz/IEDExplorer) | [libiec61850](https://github.com/mz-automation/libiec61850) |
| S7COMM  | [Snap7](http://snap7.sourceforge.net/)         | [Snap7](http://snap7.sourceforge.net/) |

In the experiments, the features were divided into three categories. For detailed information, please refer to the `features.csv` file.

## Usage

### Command-Line Arguments

The script accepts the following arguments:

| Argument               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `-p`, `--protocol`     | Name of the protocol to analysis (`bacnet`, `mms`, `s7`).     |