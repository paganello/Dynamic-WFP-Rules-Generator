# Dynamic WFP Filters Generator

**ATTENTION: the project is currently immature and still allows for little management of possible applicable rules in WFP**

Makes easy Permit/Block IPv4 CIDR in Windows Filtering Platform using low level systems calls. <br>
This document describes a custom implementation of the Windows Filtering Platform (WFP), designed to provide fine-grained control over network traffic at the system level. The implementation enables precise management of network filtering rules while seamlessly integrating with existing network security solutions.

## System Overview

The system establishes integration with the Windows networking stack through the Windows Filtering Platform API. It operates by creating a WFP session configured with specific security credentials in dynamic mode, enabling real-time modifications to filtering rules. This session serves as the foundation for all network filtering operations, managing authentication and transaction control while maintaining a secure operational context.

## Operational Framework

The system initializes by establishing a WFP session and registering a custom provider within the Windows Filtering Platform ecosystem. This registration creates a unique identity that allows the system to coexist with other networking solutions. Following provider registration, the system creates a sublayer that serves as a container for all custom filtering rules.

Network filtering rules process addresses using CIDR notation, converting network definitions into their binary representations with careful attention to proper byte ordering. Each network address and mask is stored in network byte order (big-endian) format, ensuring correct interpretation at the system level.

## Technical Implementation Details

The system implements session management through a custom structure that encapsulates the WFP session handle and related configuration. Sessions are created with the FWPM_SESSION_FLAG_DYNAMIC flag, allowing for dynamic updates to filtering rules without requiring system restarts.

### Provider and Sublayer Registration
The provider registration process generates unique GUIDs for both the provider and its sublayer. The sublayer is registered with maximum weight (^uint16(0)) to ensure proper positioning in the filtering hierarchy. This setup enables the system to maintain priority over other filtering solutions when necessary.

**This file will be updated with more details soon**



