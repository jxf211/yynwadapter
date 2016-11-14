from schematics.models import Model
from schematics.types import IntType, StringType, BooleanType, IPv4Type
from schematics.types import UUIDType
from schematics.types.compound import ListType, ModelType


class BaseModel(Model):
    def serialized_field_names(self):
        fields = []
        for k, v in self._fields.items():
            if v.serialized_name:
                fields.append(v.serialized_name)
            else:
                fields.append(k)
        return fields

    def serialized_name(self, field):
        return self._fields[field].serialized_name

    def filtered_fields(self, fields):
        r_item_dict = {}
        for k, v in self.to_primitive().items():
            if k in fields:
                r_item_dict[k] = v
        return r_item_dict


class Network(BaseModel):
    id = StringType(serialized_name='networkId')
    name = StringType(serialized_name='networkName', required=True)
    type = StringType(serialized_name='networkType', default='VXLAN')
    segmentation_id = IntType(serialized_name='segmentationId', default=0)
    external = BooleanType(serialized_name='external', default=False)


class IpAllocPool(BaseModel):
    start = IPv4Type(serialized_name='start', required=True)
    end = IPv4Type(serialized_name='end', required=True)


class Subnet(BaseModel):
    subnet_id = StringType(serialized_name="subnetId")
    subnet_name = StringType(serialized_name="subnetName")
    network_id = StringType(serialized_name='networkId')
    cidr = StringType(serialized_name='cidr')
    allocation_pools = ListType(ModelType(IpAllocPool),
                                serialized_name='allocation_pools')
    gateway_ip = IPv4Type(serialized_name='gatewayIp')
    dns_nameservers = ListType(IPv4Type, serialized_name='dnsNameservers')


class Port(BaseModel):
    id = StringType(serialized_name='portId')
    name = StringType(serialized_name='portName')
    mac_address = StringType(serialized_name='macAddress')
    fixed_ips = ListType(StringType, serialized_name='fixedIps', default=[])
    subnet_id = StringType(serialized_name='subnetId')
    network_id = StringType(serialized_name='networkId')
    device_type = StringType(serialized_name='deviceType')
    device_id = StringType(serialized_name='deviceId')
    local_vlan_id = IntType(serialized_name='localVlanId')


class ExternalFixedIps(BaseModel):
    subnet_id = StringType(serialized_name='subnetId', required=True)
    ip = IPv4Type(serialized_name='ip', required=True)


class ExternalGatewayInfo(BaseModel):
    network_id = StringType(serialized_name='networkId', required=True)
    external_fixed_ips = ListType(ModelType(ExternalFixedIps),
                                  serialized_name='externalFixedIps',
                                  default=[])


class Router(BaseModel):
    id = StringType(serialized_name='routerId')
    name = StringType(serialized_name='routerName', default='router')
    external_gateway_info = ModelType(ExternalGatewayInfo,
                                      serialized_name='externalGatewayInfo')


class FloatingIP(BaseModel):
    floatingipid = UUIDType(serialized_name='floatingIpId')
    fixedipaddress = IPv4Type(serialized_name='fixedIPAddress', default='')
    floatingipaddress = IPv4Type(serialized_name='floatingIpAddress',
                                 default='')
    floatingnetworkid = UUIDType(serialized_name='floatingNetworkId')
    portid = UUIDType(serialized_name='portId')
    routerid = UUIDType(serialized_name='routerId')


class FloatingIPCreate(BaseModel):
    floatingnetworkid = UUIDType(serialized_name='floatingNetworkId',
                                 required=True)
    floatingipaddress = IPv4Type(serialized_name='floatingIpAddress')
    portid = UUIDType(serialized_name='portId')
    fixedipaddress = IPv4Type(serialized_name='fixedIPAddress')


class FloatingIPModify(BaseModel):
    portid = UUIDType(serialized_name='portId')


class IPInfo(BaseModel):
    ip = StringType(serialized_name='ip', required=True)
    port = IntType(serialized_name='port', required=True)


class PortMapping(BaseModel):
    network_id = StringType(serialized_name='networkId')
    subnet_id = StringType(serialized_name='subnetId', required=True)
    public_ip = StringType(serialized_name='publicIp')
    public_port = IntType(serialized_name='publicPort')
    fixed_ip_info = ModelType(IPInfo, serialized_name='fixedIPInfo',
                              required=True)


class RouterInterface(BaseModel):
    subnet_id = StringType(serialized_name='subnetId')
    port_id = StringType(serialized_name='portId')


class ArpRequest(BaseModel):
    network_type = StringType(serialized_name='networkType', required=True)
    segmentation_id = StringType(serialized_name='segmentationId',
                                 required=True)
    mac_address = StringType(serialized_name='macAddress', required=False)
    ip_address = StringType(serialized_name='ipAddress', required=False)


class ArpReply(BaseModel):
    ip = StringType(serialized_name='ip')
    mac = StringType(serialized_name='mac')
    network_type = StringType(serialized_name='networkType')
    segmentation_id = IntType(serialized_name='segmentationId')


class SubnetRouteGroup(BaseModel):
    id = StringType(serialized_name='subnetRouteGroupId')
    router_id = StringType(serialized_name='routerId')
    subnets = ListType(StringType, serialized_name='subnets', default=[])
