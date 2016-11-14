DROP DATABASE IF EXISTS livecloud_openstack;

CREATE DATABASE livecloud_openstack;

USE livecloud_openstack;

CREATE TABLE IF NOT EXISTS neutron_ports (
    id                  CHAR(36) NOT NULL,
    name                VARCHAR(64),
    mac_address         CHAR(18),
    device_type         VARCHAR(64),
    device_id           CHAR(36),
    ifindex             INTEGER,
    network_id          CHAR(36),
    lcuuid              CHAR(36),
    PRIMARY KEY (id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_ports;

CREATE TABLE IF NOT EXISTS neutron_port_ip (
    port_id             CHAR(36) NOT NULL,
    subnet_id           CHAR(36),
    ip_address          CHAR(16)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_port_ip;

CREATE TABLE IF NOT EXISTS neutron_networks (
    id                  CHAR(64) NOT NULL,
    name                VARCHAR(255),
    type                CHAR(16),
    segmentation_id     INTEGER DEFAULT 0,
    external            INTEGER DEFAULT 0,
    lcuuid              CHAR(64),
    epc_id              INTEGER DEFAULT 0,
    userid              INTEGER DEFAULT 0,
    PRIMARY KEY (id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_networks;

CREATE TABLE IF NOT EXISTS neutron_subnets (
    id                  CHAR(64) NOT NULL,
    name                VARCHAR(255),
    network_id          CHAR(64) NOT NULL,
    cidr                CHAR(64) NOT NULL,
    allocation_pools    VARCHAR(1024) DEFAULT '',
    gateway_ip          VARCHAR(255) DEFAULT '',
    dns_nameservers     VARCHAR(255) DEFAULT '',
    lcuuid              CHAR(64),
    net_idx             INTEGER,
    PRIMARY KEY (id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_subnets;

CREATE TABLE IF NOT EXISTS neutron_routers (
    id                  CHAR(64) NOT NULL,
    name                VARCHAR(255),
    exlcuuid            CHAR(64),
    lcuuid              CHAR(64),
    epc_id              INTEGER DEFAULT 0,
    userid              INTEGER DEFAULT 0,
    exlcid              INTEGER DEFAULT 0,
    lcid                INTEGER DEFAULT 0,
    PRIMARY KEY (id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_routers;

CREATE TABLE IF NOT EXISTS neutron_floatingips (
    id                  CHAR(64) NOT NULL,
    fixedipaddress      CHAR(64),
    floatingipaddress   CHAR(64),
    floatingnetworkid   CHAR(64),
    portid              CHAR(64),
    routerid            CHAR(64),
    PRIMARY KEY (id)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM neutron_floatingips;

CREATE TABLE IF NOT EXISTS portmappings (
    network_id          CHAR(36),
    subnet_id           CHAR(36),
    public_ip           CHAR(16),
    public_port         INTEGER,
    ip                  CHAR(16),
    port                INTEGER
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM portmappings;

CREATE TABLE IF NOT EXISTS subnet_route_groups (
    id                  CHAR(36),
    router_id           CHAR(36),
    vgw_id              INTEGER
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM subnet_route_groups;

CREATE TABLE IF NOT EXISTS srg_subnets (
    srg_id              CHAR(36),
    subnet_id           CHAR(36)
)ENGINE=innodb DEFAULT CHARSET=utf8;
DELETE FROM srg_subnets;
